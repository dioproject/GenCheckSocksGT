use crate::checker::StageError;
use crate::checker::socks5;
use crate::model::{Endpoint, SocksTrace};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub const SERVER_DATA_BODY: &str = "version=5.61&protocol=227&platform=0";
pub const USER_AGENT: &str = "UbiServices_SDK_2022.Release.9_PC64_ansi_stati";
const MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub trace: Option<SocksTrace>,
}

#[derive(Debug, Clone)]
pub struct ServerData {
    pub status: u16,
    pub server: String,
    pub port: u16,
    pub login_url: String,
    pub meta: Option<String>,
    pub source_host: String,
    pub trace: Option<SocksTrace>,
}

#[derive(Debug, Clone)]
pub struct ExitInfo {
    pub ip: String,
    pub country: Option<String>,
}

static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn tls_config() -> Arc<rustls::ClientConfig> {
    TLS_CONFIG
        .get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

pub async fn request(
    endpoint: &Endpoint,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: String,
    timeout: Duration,
) -> Result<HttpResponse, StageError> {
    let socks = match socks5::connect(endpoint, host, port, timeout).await {
        Ok(conn) => conn,
        Err(e) => return Err(StageError::from_socks(e)),
    };
    let trace = socks.trace.clone();

    let tls = match tls_connect(socks.stream, host, timeout).await {
        Ok(stream) => stream,
        Err(mut e) => {
            e.trace = Some(trace);
            return Err(e);
        }
    };

    let mut response = match hyper_request(tls, host, method, path, body, timeout).await {
        Ok(response) => response,
        Err(mut e) => {
            e.trace = Some(trace);
            return Err(e);
        }
    };
    response.trace = Some(trace);
    Ok(response)
}

async fn tls_connect(
    stream: TcpStream,
    host: &str,
    timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, StageError> {
    let connector = TlsConnector::from(tls_config());
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| StageError::new("TLS_FAILED", format!("invalid TLS server name: {e}")))?;

    match tokio::time::timeout(timeout, connector.connect(server_name, stream)).await {
        Err(_) => Err(StageError::timeout(format!(
            "TLS handshake with {host} timed out"
        ))),
        Ok(Err(e)) => Err(StageError::new(
            "TLS_FAILED",
            format!("TLS handshake with {host} failed: {e}"),
        )),
        Ok(Ok(stream)) => Ok(stream),
    }
}

async fn hyper_request(
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    host: &str,
    method: &str,
    path: &str,
    body: String,
    timeout: Duration,
) -> Result<HttpResponse, StageError> {
    let io = TokioIo::new(tls);
    let (mut sender, conn) = match tokio::time::timeout(timeout, http1::handshake(io)).await {
        Err(_) => {
            return Err(StageError::timeout(format!(
                "HTTP handshake with {host} timed out"
            )));
        }
        Ok(Err(e)) => {
            return Err(StageError::new(
                "HTTP_FAILED",
                format!("HTTP handshake with {host} failed: {e}"),
            ));
        }
        Ok(Ok(pair)) => pair,
    };

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", host)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "*/*")
        .header("Connection", "close");
    if !body.is_empty() {
        builder = builder.header("Content-Type", "application/x-www-form-urlencoded");
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| StageError::new("HTTP_FAILED", format!("could not build request: {e}")))?;

    let response = match tokio::time::timeout(timeout, sender.send_request(request)).await {
        Err(_) => {
            return Err(StageError::timeout(format!(
                "HTTP request to {host}{path} timed out"
            )));
        }
        Ok(Err(e)) => {
            return Err(StageError::new(
                "HTTP_FAILED",
                format!("HTTP request to {host}{path} failed: {e}"),
            ));
        }
        Ok(Ok(response)) => response,
    };

    let status = response.status().as_u16();
    let body = match tokio::time::timeout(
        timeout,
        Limited::new(response.into_body(), MAX_BODY).collect(),
    )
    .await
    {
        Err(_) => {
            return Err(StageError::timeout(format!(
                "timed out reading response body from {host}"
            )));
        }
        Ok(Err(e)) => {
            return Err(StageError::new(
                "HTTP_FAILED",
                format!("failed to read response body from {host}: {e}"),
            ));
        }
        Ok(Ok(collected)) => collected.to_bytes(),
    };

    Ok(HttpResponse {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
        trace: None,
    })
}

pub async fn fetch_server_data(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<ServerData, StageError> {
    let mut last_error: Option<StageError> = None;
    let mut blocked: Option<StageError> = None;

    for host in ["www.growtopia2.com", "www.growtopia1.com"] {
        match request(
            endpoint,
            host,
            443,
            "POST",
            "/growtopia/server_data.php",
            SERVER_DATA_BODY.to_string(),
            timeout,
        )
        .await
        {
            Ok(response) => {
                if response.status == 401 || response.status == 403 {
                    blocked = Some(StageError::new(
                        "BLOCKED",
                        format!(
                            "{host} returned HTTP {}; this exit IP is likely rejected by Growtopia",
                            response.status
                        ),
                    )
                    .with_trace(response.trace));
                    continue;
                }
                if response.status >= 500 {
                    last_error = Some(
                        StageError::new(
                            "HTTP_FAILED",
                            format!("{host} returned HTTP {}", response.status),
                        )
                        .with_trace(response.trace),
                    );
                    continue;
                }
                if response.status != 200 {
                    last_error = Some(
                        StageError::new(
                            "HTTP_FAILED",
                            format!("{host} returned unexpected HTTP {}", response.status),
                        )
                        .with_trace(response.trace),
                    );
                    continue;
                }

                match parse_server_data(&response.body) {
                    Ok(mut data) => {
                        data.status = response.status;
                        data.source_host = host.to_string();
                        data.trace = response.trace;
                        return Ok(data);
                    }
                    Err(reason) => {
                        last_error = Some(
                            StageError::new(
                                "BAD_SERVER_DATA",
                                format!("{host} returned HTTP 200 but {reason}"),
                            )
                            .with_trace(response.trace),
                        );
                    }
                }
            }
            Err(e) => {
                if !retry_with_other_growtopia_host(&e.status) {
                    return Err(e);
                }
                last_error = Some(e);
            }
        }
    }

    Err(blocked.or(last_error).unwrap_or_else(|| {
        StageError::new("HTTP_FAILED", "no Growtopia server_data host was reachable")
    }))
}

fn retry_with_other_growtopia_host(status: &str) -> bool {
    matches!(
        status,
        "BLOCKED"
            | "HTTP_FAILED"
            | "BAD_SERVER_DATA"
            | "TLS_FAILED"
            | "TIMEOUT"
            | "SOCKS_CONNECT_FAILED"
    )
}

pub async fn check_login(endpoint: &Endpoint, timeout: Duration) -> Result<u16, StageError> {
    let response = request(
        endpoint,
        "login.growtopiagame.com",
        443,
        "GET",
        "/",
        String::new(),
        timeout,
    )
    .await?;

    if response.status == 401 || response.status == 403 {
        return Err(StageError::new(
            "LOGIN_FAILED",
            format!(
                "login.growtopiagame.com returned HTTP {}; this exit IP may be rejected",
                response.status
            ),
        )
        .with_trace(response.trace));
    }
    if response.status >= 500 {
        return Err(StageError::new(
            "LOGIN_FAILED",
            format!("login.growtopiagame.com returned HTTP {}", response.status),
        )
        .with_trace(response.trace));
    }
    Ok(response.status)
}

pub async fn fetch_exit_info(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<ExitInfo, StageError> {
    let cloudflare = request(
        endpoint,
        "www.cloudflare.com",
        443,
        "GET",
        "/cdn-cgi/trace",
        String::new(),
        timeout,
    )
    .await;
    if let Ok(response) = &cloudflare
        && response.status == 200
        && let Some(info) = parse_cloudflare_trace(&response.body)
    {
        return Ok(info);
    }

    let ipify = request(
        endpoint,
        "api.ipify.org",
        443,
        "GET",
        "/?format=json",
        String::new(),
        timeout,
    )
    .await;
    if let Ok(response) = &ipify
        && response.status == 200
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(&response.body)
        && let Some(ip) = value.get("ip").and_then(|v| v.as_str())
    {
        return Ok(ExitInfo {
            ip: ip.to_string(),
            country: None,
        });
    }

    let mut error = ipify.err().or(cloudflare.err()).unwrap_or_else(|| {
        StageError::new(
            "EXIT_IP_FAILED",
            "could not read an exit IP from Cloudflare or ipify",
        )
    });
    if error.message.is_empty() {
        error.message = "could not read an exit IP from Cloudflare or ipify".to_string();
    }
    Err(error)
}

fn parse_cloudflare_trace(body: &str) -> Option<ExitInfo> {
    let mut ip = None;
    let mut country = None;
    for line in body.lines() {
        if let Some(value) = line.strip_prefix("ip=") {
            let value = value.trim();
            if !value.is_empty() {
                ip = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("loc=") {
            let value = value.trim();
            if !value.is_empty() {
                country = Some(value.to_string());
            }
        }
    }
    ip.map(|ip| ExitInfo { ip, country })
}

pub fn parse_server_data(body: &str) -> Result<ServerData, String> {
    let server = get_value(body, "server").ok_or_else(|| "missing `server|` field".to_string())?;
    let port_str = get_value(body, "port").ok_or_else(|| "missing `port|` field".to_string())?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port field: {port_str}"))?;
    if server.trim().is_empty() {
        return Err("empty `server|` field".to_string());
    }
    let login_url = get_value(body, "loginurl")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "login.growtopiagame.com".to_string());
    let meta = get_value(body, "meta").filter(|v| !v.is_empty());
    Ok(ServerData {
        status: 200,
        server: server.trim().to_string(),
        port,
        login_url,
        meta,
        source_host: String::new(),
        trace: None,
    })
}

fn get_value(body: &str, key: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if let Some((name, value)) = line.split_once('|')
            && name.trim() == key
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_data() {
        let body =
            "server|213.179.209.175\nport|17042\nloginurl|login.growtopiagame.com\nmeta|abc\n";
        let data = parse_server_data(body).unwrap();
        assert_eq!(data.server, "213.179.209.175");
        assert_eq!(data.port, 17042);
        assert_eq!(data.login_url, "login.growtopiagame.com");
        assert_eq!(data.meta.as_deref(), Some("abc"));
    }

    #[test]
    fn rejects_missing_server_data_fields() {
        assert!(parse_server_data("server|1.2.3.4\n").is_err());
        assert!(parse_server_data("port|1234\n").is_err());
        assert!(parse_server_data("server|1.2.3.4\nport|abc\n").is_err());
    }

    #[test]
    fn parses_cloudflare_trace() {
        let body = "fl=abc\nip=203.0.113.7\nts=1\nloc=ID\n";
        let info = parse_cloudflare_trace(body).unwrap();
        assert_eq!(info.ip, "203.0.113.7");
        assert_eq!(info.country.as_deref(), Some("ID"));
    }
}
