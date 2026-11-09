use crate::checker::StageError;
use crate::checker::socks5;
use crate::model::Endpoint;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

const DNS_NAME: &str = "www.growtopia2.com";
const DNS_SERVERS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];

pub async fn check(endpoint: &Endpoint, timeout: Duration) -> Result<(), StageError> {
    let conn = match socks5::udp_associate(endpoint, timeout).await {
        Ok(conn) => conn,
        Err(e) => {
            if e.reply_code == Some(0x07) {
                return Err(StageError::new(
                    "UNSUPPORTED",
                    "proxy does not support SOCKS5 UDP ASSOCIATE (TCP-only proxy)",
                )
                .with_trace(Some(e.trace)));
            }
            return Err(StageError::from_socks(e));
        }
    };

    // Keep the TCP control connection alive while the UDP relay is tested.
    let _control = conn.stream;
    let relay = match conn.bound {
        Some(addr) => addr,
        None => {
            return Err(StageError::new(
                "UDP_FAILED",
                "SOCKS5 UDP ASSOCIATE returned no relay address",
            )
            .with_trace(Some(conn.trace)));
        }
    };
    if relay.port() == 0 {
        return Err(
            StageError::new("UDP_FAILED", "SOCKS5 UDP ASSOCIATE returned relay port 0")
                .with_trace(Some(conn.trace)),
        );
    }

    let relay = if relay.ip().is_unspecified() {
        let proxy_ip = conn
            .trace
            .proxy_resolved
            .as_deref()
            .and_then(|value| value.parse::<IpAddr>().ok())
            .ok_or_else(|| {
                StageError::new(
                    "UDP_FAILED",
                    "could not determine the proxy IP for the UDP relay",
                )
                .with_trace(Some(conn.trace.clone()))
            })?;
        SocketAddr::new(proxy_ip, relay.port())
    } else {
        relay
    };

    let bind_addr = if relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
        StageError::new("UDP_FAILED", format!("could not bind UDP socket: {e}"))
            .with_trace(Some(conn.trace.clone()))
    })?;

    let dns_id: u16 = rand::random();
    let dns_query = build_dns_query(DNS_NAME, dns_id);
    let udp_timeout = timeout.min(Duration::from_secs(5));

    for server in DNS_SERVERS {
        let packet = wrap_udp_packet(server, 53, &dns_query);
        if let Err(e) = socket.send_to(&packet, relay).await {
            return Err(StageError::new(
                "UDP_FAILED",
                format!("failed to send UDP probe to relay {relay}: {e}"),
            )
            .with_trace(Some(conn.trace)));
        }

        let mut buf = [0u8; 2048];
        match tokio::time::timeout(udp_timeout, socket.recv_from(&mut buf)).await {
            Err(_) => continue,
            Ok(Err(e)) => {
                return Err(StageError::new(
                    "UDP_FAILED",
                    format!("UDP receive from relay {relay} failed: {e}"),
                )
                .with_trace(Some(conn.trace)));
            }
            Ok(Ok((n, _from))) => {
                if let Some(payload) = parse_udp_packet(&buf[..n])
                    && dns_response_matches(payload, dns_id)
                {
                    return Ok(());
                }
            }
        }
    }

    Err(StageError::new(
        "UDP_FAILED",
        format!("UDP relay {relay} did not return a valid DNS response"),
    )
    .with_trace(Some(conn.trace)))
}

fn wrap_udp_packet(dst: Ipv4Addr, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn parse_udp_packet(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 10 {
        return None;
    }
    if packet[0] != 0x00 || packet[1] != 0x00 || packet[2] != 0x00 {
        return None;
    }
    let atyp = packet[3];
    let offset = match atyp {
        0x01 => {
            if packet.len() < 10 {
                return None;
            }
            10
        }
        0x03 => {
            if packet.len() < 5 {
                return None;
            }
            let len = packet[4] as usize;
            if packet.len() < 5 + len + 2 {
                return None;
            }
            5 + len + 2
        }
        0x04 => {
            if packet.len() < 22 {
                return None;
            }
            22
        }
        _ => return None,
    };
    Some(&packet[offset..])
}

fn build_dns_query(name: &str, id: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(12 + name.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // recursion desired
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x01]); // QTYPE A
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    query
}

fn dns_response_matches(payload: &[u8], id: u16) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let response_id = u16::from_be_bytes([payload[0], payload[1]]);
    if response_id != id {
        return false;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    flags & 0x8000 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_and_parses_udp_packet() {
        let payload = b"hello";
        let packet = wrap_udp_packet(Ipv4Addr::new(1, 1, 1, 1), 53, payload);
        assert_eq!(parse_udp_packet(&packet), Some(payload.as_slice()));
    }

    #[test]
    fn builds_dns_query_with_id() {
        let query = build_dns_query("example.com", 0x1234);
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert_eq!(&query[4..6], &[0x00, 0x01]);
        assert!(query.windows(7).any(|w| w == b"example"));
    }

    #[test]
    fn checks_dns_response_id_and_qr_bit() {
        let mut payload = vec![0u8; 12];
        payload[0] = 0x12;
        payload[1] = 0x34;
        payload[2] = 0x80;
        assert!(dns_response_matches(&payload, 0x1234));
        assert!(!dns_response_matches(&payload, 0x1235));
    }
}
