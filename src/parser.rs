use crate::model::Endpoint;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct ParseIssue {
    pub line: usize,
    pub raw: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct LoadResult {
    pub endpoints: Vec<Endpoint>,
    pub issues: Vec<ParseIssue>,
    pub duplicates: usize,
}

pub fn load_endpoints(input: &str, dedup: bool) -> Result<LoadResult> {
    let raw = if input == "-" || input.is_empty() {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read stdin")?;
        buf
    } else {
        std::fs::read_to_string(input)
            .with_context(|| format!("failed to read input file: {input}"))?
    };

    let mut endpoints = Vec::new();
    let mut issues = Vec::new();
    let mut seen = HashSet::new();
    let mut duplicates = 0usize;

    for (idx, raw_line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_endpoint(line) {
            Ok(endpoint) => {
                if dedup && !seen.insert(endpoint.key()) {
                    duplicates += 1;
                    continue;
                }
                if !dedup {
                    seen.insert(endpoint.key());
                }
                endpoints.push(endpoint);
            }
            Err(reason) => issues.push(ParseIssue {
                line: line_no,
                raw: line.to_string(),
                reason,
            }),
        }
    }

    Ok(LoadResult {
        endpoints,
        issues,
        duplicates,
    })
}

pub fn parse_endpoint(input: &str) -> std::result::Result<Endpoint, String> {
    let original = input.trim();
    if original.is_empty() {
        return Err("empty line".to_string());
    }

    let line = strip_scheme(original)?;

    if looks_like_pipe(line) {
        return parse_pipe(line);
    }

    // URL/userinfo form: user:pass@host:port. Only treat this as a
    // userinfo prefix when the left side is plausible credentials (zero or
    // one colon); otherwise a colon-format password may legitimately contain
    // '@' and ':port' (e.g. host:1080:user:p@ss:1234).
    if let Some((left, right)) = line.rsplit_once('@')
        && !left.is_empty()
        && left.matches(':').count() <= 1
        && right.contains(':')
        && split_host_port(right).is_ok()
    {
        let (username, password) = match left.split_once(':') {
            Some((u, p)) => (percent_decode(u), percent_decode(p)),
            None => (percent_decode(left), String::new()),
        };
        let (host, port) = split_host_port(right)?;
        return make_endpoint(host, port, username, password);
    }

    parse_colon(line)
}

fn strip_scheme(input: &str) -> std::result::Result<&str, String> {
    let lower = input.to_ascii_lowercase();
    for prefix in ["socks5h://", "socks5://"] {
        if lower.starts_with(prefix) {
            return Ok(&input[prefix.len()..]);
        }
    }
    for prefix in ["socks4a://", "socks4://"] {
        if lower.starts_with(prefix) {
            return Err("SOCKS4 is not supported; use a SOCKS5 endpoint".to_string());
        }
    }
    for prefix in ["http://", "https://"] {
        if lower.starts_with(prefix) {
            return Err("HTTP proxy URL detected; use a SOCKS5 endpoint".to_string());
        }
    }
    Ok(input)
}

fn looks_like_pipe(line: &str) -> bool {
    if !line.contains('|') {
        return false;
    }
    let parts: Vec<&str> = line.splitn(3, '|').collect();
    if parts.len() < 2 {
        return false;
    }
    let host = parts[0].trim();
    let host_ok = if host.starts_with('[') {
        host.ends_with(']')
    } else {
        !host.contains(':') || host.parse::<std::net::IpAddr>().is_ok()
    };
    host_ok && parts[1].trim().parse::<u16>().is_ok()
}

fn parse_pipe(line: &str) -> std::result::Result<Endpoint, String> {
    let parts: Vec<&str> = line.splitn(4, '|').collect();
    if parts.len() < 2 {
        return Err("pipe format must be host|port or host|port|user|pass".to_string());
    }
    let host = parts[0].trim();
    let port = parse_port(parts[1].trim())?;
    let username = parts
        .get(2)
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let password = parts
        .get(3)
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    make_endpoint(host.to_string(), port, username, password)
}

fn parse_colon(line: &str) -> std::result::Result<Endpoint, String> {
    if line.starts_with('[') {
        let end = line
            .find(']')
            .ok_or_else(|| "missing ] in IPv6 host".to_string())?;
        let host = &line[1..end];
        let rest = &line[end + 1..];
        let rest = rest
            .strip_prefix(':')
            .ok_or_else(|| "missing port after IPv6 host".to_string())?;
        let mut parts = rest.splitn(3, ':');
        let port = parse_port(
            parts
                .next()
                .ok_or_else(|| "missing port after IPv6 host".to_string())?
                .trim(),
        )?;
        let username = parts
            .next()
            .map(|v| v.trim().to_string())
            .unwrap_or_default();
        let password = parts
            .next()
            .map(|v| v.trim().to_string())
            .unwrap_or_default();
        return make_endpoint(host.to_string(), port, username, password);
    }

    // splitn(4) keeps the rest of the password in the last field, so
    // host:port:user:pa:ss is parsed as password "pa:ss".
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() < 2 {
        return Err("colon format must be host:port[:user[:pass]]".to_string());
    }
    let host = parts[0].trim();
    let port = parse_port(parts[1].trim())?;
    let username = parts
        .get(2)
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let password = parts
        .get(3)
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    make_endpoint(host.to_string(), port, username, password)
}

fn split_host_port(input: &str) -> std::result::Result<(String, u16), String> {
    let input = input.trim();
    if let Some(rest) = input.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "missing ] in IPv6 host".to_string())?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| "missing port after IPv6 host".to_string())?;
        let port = parse_port(port_str.trim())?;
        return Ok((host.to_string(), port));
    }

    let (host, port_str) = input
        .rsplit_once(':')
        .ok_or_else(|| "missing port; expected host:port".to_string())?;
    if host.contains(':') {
        return Err("IPv6 host must be wrapped in []".to_string());
    }
    let port = parse_port(port_str.trim())?;
    Ok((host.trim().to_string(), port))
}

fn parse_port(input: &str) -> std::result::Result<u16, String> {
    let port: u16 = input
        .parse()
        .map_err(|_| format!("invalid port: {input}"))?;
    if port == 0 {
        return Err("port must be 1-65535".to_string());
    }
    Ok(port)
}

fn make_endpoint(
    host: String,
    port: u16,
    username: String,
    password: String,
) -> std::result::Result<Endpoint, String> {
    let mut host = host.trim().to_string();
    if host.starts_with('[') && host.ends_with(']') {
        host = host[1..host.len() - 1].to_string();
    }
    if host.is_empty() {
        return Err("host is empty".to_string());
    }
    if host.len() > 255 {
        return Err("host is too long".to_string());
    }
    if host.contains(char::is_whitespace) {
        return Err("host contains whitespace".to_string());
    }
    if host.contains('/') || host.contains('@') || host.contains('|') {
        return Err("host contains an invalid character".to_string());
    }
    Ok(Endpoint {
        host,
        port,
        username,
        password,
    })
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push(hi * 16 + lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_with_auth() {
        let ep = parse_endpoint("1.2.3.4:1080:bob:secret").unwrap();
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.port, 1080);
        assert_eq!(ep.username, "bob");
        assert_eq!(ep.password, "secret");
    }

    #[test]
    fn parses_pipe_with_auth() {
        let ep = parse_endpoint("proxy.example.com|30424|user|p@ss:word").unwrap();
        assert_eq!(ep.host, "proxy.example.com");
        assert_eq!(ep.port, 30424);
        assert_eq!(ep.username, "user");
        assert_eq!(ep.password, "p@ss:word");
    }

    #[test]
    fn parses_password_with_colons_in_colon_format() {
        let ep = parse_endpoint("host.example:1080:user:pa:ss:word").unwrap();
        assert_eq!(ep.password, "pa:ss:word");
    }

    #[test]
    fn parses_url_with_percent_encoded_credentials() {
        let ep = parse_endpoint("socks5://user%40name:p%3Ass@host.example:1080").unwrap();
        assert_eq!(ep.username, "user@name");
        assert_eq!(ep.password, "p:ss");
        assert_eq!(ep.host, "host.example");
    }

    #[test]
    fn parses_userinfo_at_form() {
        let ep = parse_endpoint("bob:secret@1.2.3.4:1080").unwrap();
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.username, "bob");
        assert_eq!(ep.password, "secret");
    }

    #[test]
    fn parses_ipv6() {
        let ep = parse_endpoint("[2001:db8::1]:1080:user:pass").unwrap();
        assert_eq!(ep.host, "2001:db8::1");
        assert_eq!(ep.port, 1080);
        assert_eq!(ep.to_colon(), "[2001:db8::1]:1080:user:pass");
    }

    #[test]
    fn rejects_bad_port() {
        assert!(parse_endpoint("host:0").is_err());
        assert!(parse_endpoint("host:abc").is_err());
    }

    #[test]
    fn rejects_http_proxy_url() {
        let err = parse_endpoint("http://1.2.3.4:8080").unwrap_err();
        assert!(err.contains("HTTP proxy"));
    }

    #[test]
    fn password_can_contain_at_when_it_is_not_userinfo() {
        let ep = parse_endpoint("host:1080:user:p@ss").unwrap();
        assert_eq!(ep.password, "p@ss");
    }

    #[test]
    fn password_with_at_and_port_like_suffix_is_not_userinfo() {
        let ep = parse_endpoint("host:1080:user:p@ss:1234").unwrap();
        assert_eq!(ep.host, "host");
        assert_eq!(ep.port, 1080);
        assert_eq!(ep.username, "user");
        assert_eq!(ep.password, "p@ss:1234");
    }

    #[test]
    fn ipv6_pipe_round_trips() {
        let ep = parse_endpoint("2001:db8::1|1080|user|pass").unwrap();
        assert_eq!(ep.host, "2001:db8::1");
        assert_eq!(ep.to_pipe(), "2001:db8::1|1080|user|pass");
        assert_eq!(parse_endpoint(&ep.to_pipe()).unwrap().host, "2001:db8::1");
    }

    #[test]
    fn round_trips_colon_and_pipe() {
        let ep = parse_endpoint("host.example:1080:user:pa:ss").unwrap();
        let colon = ep.to_colon();
        let pipe = ep.to_pipe();
        assert_eq!(parse_endpoint(&colon).unwrap().password, "pa:ss");
        assert_eq!(parse_endpoint(&pipe).unwrap().password, "pa:ss");
    }
}
