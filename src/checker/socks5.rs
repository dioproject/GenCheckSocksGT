use crate::model::{Endpoint, SocksTrace};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const STATUS_DNS_FAILED: &str = "DNS_FAILED";
pub const STATUS_TCP_FAILED: &str = "TCP_FAILED";
pub const STATUS_TIMEOUT: &str = "TIMEOUT";
pub const STATUS_NOT_SOCKS5: &str = "NOT_SOCKS5";
pub const STATUS_NO_AUTH_METHOD: &str = "SOCKS_NO_AUTH_METHOD";
pub const STATUS_AUTH_FAILED: &str = "SOCKS_AUTH_FAILED";
pub const STATUS_CONNECT_FAILED: &str = "SOCKS_CONNECT_FAILED";
pub const STATUS_BAD_REPLY: &str = "SOCKS_BAD_REPLY";
pub const STATUS_INVALID_CONFIG: &str = "INVALID_CONFIG";
pub const STATUS_IO_ERROR: &str = "IO_ERROR";

#[derive(Debug, Clone)]
pub struct SocksError {
    pub status: &'static str,
    pub message: String,
    pub trace: SocksTrace,
    pub reply_code: Option<u8>,
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for SocksError {}

#[derive(Debug)]
pub struct Socks5Connection {
    pub stream: TcpStream,
    pub trace: SocksTrace,
    pub bound: Option<SocketAddr>,
}

pub async fn connect(
    endpoint: &Endpoint,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<Socks5Connection, SocksError> {
    handshake(endpoint, 0x01, target_host, target_port, "CONNECT", timeout).await
}

pub async fn udp_associate(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<Socks5Connection, SocksError> {
    handshake(endpoint, 0x03, "0.0.0.0", 0, "UDP ASSOCIATE", timeout).await
}

async fn handshake(
    endpoint: &Endpoint,
    command: u8,
    target_host: &str,
    target_port: u16,
    command_name: &str,
    timeout: Duration,
) -> Result<Socks5Connection, SocksError> {
    let mut trace = SocksTrace {
        target: format!("{target_host}:{target_port}"),
        command: command_name.to_string(),
        ..SocksTrace::default()
    };

    let proxy_addrs = match resolve_proxy(endpoint, timeout).await {
        Ok(addrs) => addrs,
        Err((status, message)) => {
            return Err(fail(status, message, &trace));
        }
    };
    trace.events.push(format!(
        "resolve proxy {} -> {} candidate(s)",
        endpoint.host,
        proxy_addrs.len()
    ));

    let tcp_start = Instant::now();
    let mut connected: Option<(TcpStream, SocketAddr)> = None;
    let mut last_tcp_error: Option<(&'static str, String)> = None;
    for proxy_addr in &proxy_addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(proxy_addr)).await {
            Err(_) => {
                last_tcp_error = Some((
                    STATUS_TIMEOUT,
                    format!("TCP connect to {proxy_addr} timed out"),
                ));
            }
            Ok(Err(e)) => {
                last_tcp_error = Some((
                    STATUS_TCP_FAILED,
                    format!("TCP connect to {proxy_addr} failed: {e}"),
                ));
            }
            Ok(Ok(stream)) => {
                connected = Some((stream, *proxy_addr));
                break;
            }
        }
    }

    let (mut stream, proxy_addr) = match connected {
        Some(value) => value,
        None => {
            let (status, message) = last_tcp_error.unwrap_or((
                STATUS_TCP_FAILED,
                format!("could not connect to {}:{}", endpoint.host, endpoint.port),
            ));
            return Err(fail(status, message, &trace));
        }
    };
    let _ = stream.set_nodelay(true);
    trace.proxy_resolved = Some(proxy_addr.ip().to_string());
    trace.tcp_ms = tcp_start.elapsed().as_millis() as u64;
    trace
        .events
        .push(format!("tcp connect {proxy_addr} {}ms", trace.tcp_ms));

    // SOCKS5 greeting. Offer no-auth and username/password when credentials
    // are present; offering only no-auth when the proxy needs auth produces a
    // less useful error.
    let methods: &[u8] = if endpoint.username.is_empty() {
        &[0x00]
    } else {
        &[0x00, 0x02]
    };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(methods);
    trace.greeting_sent = format_preview(&greeting);
    trace
        .events
        .push(format!("send greeting {}", trace.greeting_sent));

    let greeting_start = Instant::now();
    write_all(&mut stream, &greeting, timeout, &trace).await?;
    let mut reply = [0u8; 2];
    read_exact(&mut stream, &mut reply, timeout, &trace).await?;
    trace.greeting_ms = greeting_start.elapsed().as_millis() as u64;
    trace.greeting_recv = format_preview(&reply);

    if reply[0] != 0x05 {
        let preview = read_preview(&mut stream, &reply).await;
        trace.raw_preview = Some(preview.clone());
        trace.greeting_recv = preview.clone();
        trace
            .events
            .push(format!("unexpected greeting reply: {preview}"));
        return Err(fail(
            STATUS_NOT_SOCKS5,
            format!("endpoint is not a SOCKS5 proxy; reply starts with: {preview}"),
            &trace,
        ));
    }

    let method = reply[1];
    trace.method = Some(method);
    trace
        .events
        .push(format!("proxy selected auth method 0x{method:02x}"));

    match method {
        0x00 => {}
        0x02 => {
            if endpoint.username.is_empty() {
                return Err(fail(
                    STATUS_AUTH_FAILED,
                    "proxy requires username/password but none were supplied",
                    &trace,
                ));
            }
            if endpoint.username.len() > 255 || endpoint.password.len() > 255 {
                return Err(fail(
                    STATUS_INVALID_CONFIG,
                    "SOCKS5 username/password must be at most 255 bytes each",
                    &trace,
                ));
            }
            let auth_start = Instant::now();
            let mut auth = vec![0x01, endpoint.username.len() as u8];
            auth.extend_from_slice(endpoint.username.as_bytes());
            auth.push(endpoint.password.len() as u8);
            auth.extend_from_slice(endpoint.password.as_bytes());
            trace.events.push(format!(
                "send username/password auth ({} bytes)",
                auth.len()
            ));
            write_all(&mut stream, &auth, timeout, &trace).await?;
            let mut auth_reply = [0u8; 2];
            read_exact(&mut stream, &mut auth_reply, timeout, &trace).await?;
            trace.auth_ms = auth_start.elapsed().as_millis() as u64;
            trace.auth_status = Some(auth_reply[1]);
            trace
                .events
                .push(format!("auth reply status 0x{:02x}", auth_reply[1]));
            if auth_reply[0] != 0x01 {
                let preview = read_preview(&mut stream, &auth_reply).await;
                trace.raw_preview = Some(preview.clone());
                return Err(fail(
                    STATUS_BAD_REPLY,
                    format!("invalid SOCKS5 auth reply: {preview}"),
                    &trace,
                ));
            }
            if auth_reply[1] != 0x00 {
                return Err(fail(
                    STATUS_AUTH_FAILED,
                    format!(
                        "SOCKS5 authentication failed (status 0x{:02x})",
                        auth_reply[1]
                    ),
                    &trace,
                ));
            }
        }
        0xFF => {
            return Err(fail(
                STATUS_NO_AUTH_METHOD,
                "proxy rejected all offered authentication methods",
                &trace,
            ));
        }
        other => {
            return Err(fail(
                STATUS_BAD_REPLY,
                format!("proxy selected unsupported auth method 0x{other:02x}"),
                &trace,
            ));
        }
    }

    // CONNECT / UDP ASSOCIATE.
    let target = match encode_target(target_host, target_port) {
        Ok(v) => v,
        Err(e) => {
            return Err(fail(STATUS_INVALID_CONFIG, e, &trace));
        }
    };
    let mut request = vec![0x05, command, 0x00];
    request.extend_from_slice(&target);
    trace.events.push(format!(
        "send {} request for {} ({} bytes)",
        command_name,
        trace.target,
        request.len()
    ));

    let connect_start = Instant::now();
    write_all(&mut stream, &request, timeout, &trace).await?;

    let mut header = [0u8; 4];
    read_exact(&mut stream, &mut header, timeout, &trace).await?;
    trace.connect_ms = connect_start.elapsed().as_millis() as u64;

    if header[0] != 0x05 {
        let preview = read_preview(&mut stream, &header).await;
        trace.raw_preview = Some(preview.clone());
        return Err(fail(
            STATUS_BAD_REPLY,
            format!("invalid SOCKS5 reply version; got: {preview}"),
            &trace,
        ));
    }
    if header[2] != 0x00 {
        let preview = read_preview(&mut stream, &header).await;
        trace.raw_preview = Some(preview.clone());
        return Err(fail(
            STATUS_BAD_REPLY,
            format!(
                "invalid SOCKS5 reserved byte 0x{:02x}: {preview}",
                header[2]
            ),
            &trace,
        ));
    }

    let rep = header[1];
    trace.reply_code = Some(rep);
    trace.reply_text = Some(rep_text(rep).to_string());
    trace.events.push(format!(
        "{} reply 0x{:02x} ({})",
        command_name,
        rep,
        rep_text(rep)
    ));

    if rep != 0x00 {
        let preview = read_preview(&mut stream, &header).await;
        trace.raw_preview = Some(preview.clone());
        let mut error = fail(
            STATUS_CONNECT_FAILED,
            format!(
                "SOCKS5 {} failed: {} (reply 0x{:02x})",
                command_name,
                rep_text(rep),
                rep
            ),
            &trace,
        );
        error.reply_code = Some(rep);
        return Err(error);
    }

    let bound = match read_bound(&mut stream, header[3], timeout, &trace).await {
        Ok(addr) => addr,
        Err(e) => return Err(e),
    };
    trace.events.push(format!(
        "bound/relay address: {}",
        bound
            .map(|a| a.to_string())
            .unwrap_or_else(|| "domain (unresolved)".to_string())
    ));

    Ok(Socks5Connection {
        stream,
        trace,
        bound,
    })
}

async fn resolve_proxy(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, (&'static str, String)> {
    if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, endpoint.port)]);
    }
    let lookup = tokio::time::timeout(
        timeout,
        tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| {
        (
            STATUS_TIMEOUT,
            format!(
                "DNS lookup for {}:{} timed out",
                endpoint.host, endpoint.port
            ),
        )
    })?
    .map_err(|e| {
        (
            STATUS_DNS_FAILED,
            format!(
                "DNS lookup for {}:{} failed: {e}",
                endpoint.host, endpoint.port
            ),
        )
    })?;

    let addrs: Vec<SocketAddr> = lookup.collect();
    if addrs.is_empty() {
        return Err((
            STATUS_DNS_FAILED,
            format!(
                "DNS lookup for {}:{} returned no address",
                endpoint.host, endpoint.port
            ),
        ));
    }
    Ok(addrs)
}

async fn read_exact(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: Duration,
    trace: &SocksTrace,
) -> Result<(), SocksError> {
    match tokio::time::timeout(timeout, stream.read_exact(buf)).await {
        Err(_) => Err(fail(
            STATUS_TIMEOUT,
            "timed out while waiting for a SOCKS5 reply",
            trace,
        )),
        Ok(Err(e)) => Err(fail(
            STATUS_BAD_REPLY,
            format!("connection closed or short SOCKS5 reply: {e}"),
            trace,
        )),
        Ok(Ok(_)) => Ok(()),
    }
}

async fn write_all(
    stream: &mut TcpStream,
    data: &[u8],
    timeout: Duration,
    trace: &SocksTrace,
) -> Result<(), SocksError> {
    match tokio::time::timeout(timeout, stream.write_all(data)).await {
        Err(_) => Err(fail(
            STATUS_TIMEOUT,
            "timed out while sending SOCKS5 request",
            trace,
        )),
        Ok(Err(e)) => Err(fail(
            STATUS_IO_ERROR,
            format!("failed to send SOCKS5 request: {e}"),
            trace,
        )),
        Ok(Ok(())) => Ok(()),
    }
}

async fn read_bound(
    stream: &mut TcpStream,
    atyp: u8,
    timeout: Duration,
    trace: &SocksTrace,
) -> Result<Option<SocketAddr>, SocksError> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            read_exact(stream, &mut buf, timeout, trace).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            read_exact(stream, &mut buf, timeout, trace).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(Some(SocketAddr::new(IpAddr::V6(ip), port)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len, timeout, trace).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            read_exact(stream, &mut buf, timeout, trace).await?;
            let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
            // A domain in BND.ADDR is legal but not useful for UDP relay.
            // Use the unspecified IPv4 address; the caller substitutes the
            // proxy IP while keeping this port.
            Ok(Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                port,
            )))
        }
        other => Err(fail(
            STATUS_BAD_REPLY,
            format!("SOCKS5 reply used unsupported address type 0x{other:02x}"),
            trace,
        )),
    }
}

async fn read_preview(stream: &mut TcpStream, initial: &[u8]) -> String {
    let mut buf = initial.to_vec();
    let mut extra = [0u8; 128];
    if let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(200), stream.read(&mut extra)).await
        && n > 0
    {
        buf.extend_from_slice(&extra[..n]);
    }
    format_preview(&buf)
}

fn encode_target(host: &str, port: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if host.len() > 255 {
            return Err("target hostname is too long for SOCKS5".to_string());
        }
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

pub fn format_preview(bytes: &[u8]) -> String {
    let shown = &bytes[..bytes.len().min(96)];
    let ascii: String = shown
        .iter()
        .map(|&b| {
            if (32..=126).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    let hex = shown
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("ascii=\"{ascii}\" hex=[{hex}]")
}

fn rep_text(code: u8) -> &'static str {
    match code {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 error",
    }
}

fn fail(status: &'static str, message: impl Into<String>, trace: &SocksTrace) -> SocksError {
    SocksError {
        status,
        message: message.into(),
        trace: trace.clone(),
        reply_code: trace.reply_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn encodes_ipv4_target() {
        let bytes = encode_target("1.2.3.4", 1080).unwrap();
        assert_eq!(&bytes[..5], &[0x01, 1, 2, 3, 4]);
        assert_eq!(&bytes[5..7], &[0x04, 0x38]);
    }

    #[test]
    fn encodes_domain_target() {
        let bytes = encode_target("example.com", 443).unwrap();
        assert_eq!(bytes[0], 0x03);
        assert_eq!(bytes[1], 11);
        assert_eq!(&bytes[2..13], b"example.com");
        assert_eq!(&bytes[13..15], &[0x01, 0xbb]);
    }

    #[test]
    fn preview_is_printable() {
        let p = format_preview(b"HTTP/1.1 400 Bad Request\r\n");
        assert!(p.contains("HTTP/1.1 400 Bad Request"));
    }

    #[test]
    fn reply_text_maps_known_codes() {
        assert_eq!(rep_text(0x05), "connection refused");
        assert_eq!(rep_text(0x07), "command not supported");
    }

    #[tokio::test]
    async fn detects_http_proxy_on_socks_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let endpoint = Endpoint {
            host: "127.0.0.1".to_string(),
            port,
            username: String::new(),
            password: String::new(),
        };
        let error = connect(&endpoint, "example.com", 443, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert_eq!(error.status, STATUS_NOT_SOCKS5);
        assert!(error.message.contains("HTTP/1.1 400 Bad Request"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reports_auth_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x02]).await.unwrap();
            let mut auth = [0u8; 5];
            stream.read_exact(&mut auth).await.unwrap();
            stream.write_all(&[0x01, 0x01]).await.unwrap();
        });

        let endpoint = Endpoint {
            host: "127.0.0.1".to_string(),
            port,
            username: "u".to_string(),
            password: "p".to_string(),
        };
        let error = connect(&endpoint, "example.com", 443, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert_eq!(error.status, STATUS_AUTH_FAILED);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn completes_connect_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0x05);
            assert_eq!(header[1], 0x01);
            match header[3] {
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await.unwrap();
                    let mut rest = vec![0u8; len[0] as usize + 2];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                _ => panic!("expected domain target"),
            }
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
                .await
                .unwrap();
        });

        let endpoint = Endpoint {
            host: "127.0.0.1".to_string(),
            port,
            username: String::new(),
            password: String::new(),
        };
        let conn = connect(&endpoint, "example.com", 443, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(conn.trace.reply_code, Some(0));
        assert_eq!(
            conn.bound,
            Some("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
        );
        server.await.unwrap();
    }
}
