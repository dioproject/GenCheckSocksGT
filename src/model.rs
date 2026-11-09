use serde::Serialize;

/// One SOCKS5 endpoint. The password is deliberately skipped when serializing
/// reports so `results.json` never contains proxy credentials.
#[derive(Debug, Clone, Serialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
}

impl Endpoint {
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.host.to_ascii_lowercase(),
            self.port,
            self.username,
            self.password
        )
    }

    fn host_for_colon(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    pub fn to_colon(&self) -> String {
        if self.username.is_empty() {
            format!("{}:{}", self.host_for_colon(), self.port)
        } else if self.password.is_empty() {
            format!("{}:{}:{}", self.host_for_colon(), self.port, self.username)
        } else {
            format!(
                "{}:{}:{}:{}",
                self.host_for_colon(),
                self.port,
                self.username,
                self.password
            )
        }
    }

    pub fn to_pipe(&self) -> String {
        if self.username.is_empty() && self.password.is_empty() {
            format!("{}|{}", self.host, self.port)
        } else if self.password.is_empty() {
            format!("{}|{}|{}", self.host, self.port, self.username)
        } else {
            format!(
                "{}|{}|{}|{}",
                self.host, self.port, self.username, self.password
            )
        }
    }

    pub fn masked(&self) -> String {
        if self.username.is_empty() {
            format!("{}:{}", self.host_for_colon(), self.port)
        } else {
            format!(
                "{}:{}:{}:***",
                self.host_for_colon(),
                self.port,
                self.username
            )
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StageInfo {
    pub status: String,
    pub ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl StageInfo {
    pub fn ok(ms: u64) -> Self {
        Self {
            status: "OK".to_string(),
            ms,
            error: None,
        }
    }

    pub fn failed(status: impl Into<String>, ms: u64, error: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            ms,
            error: Some(error.into()),
        }
    }

    pub fn skipped() -> Self {
        Self {
            status: "SKIPPED".to_string(),
            ms: 0,
            error: None,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.status == "OK"
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SocksTrace {
    pub proxy_resolved: Option<String>,
    pub target: String,
    pub command: String,
    pub tcp_ms: u64,
    pub greeting_ms: u64,
    pub auth_ms: u64,
    pub connect_ms: u64,
    pub greeting_sent: String,
    pub greeting_recv: String,
    pub method: Option<u8>,
    pub auth_status: Option<u8>,
    pub reply_code: Option<u8>,
    pub reply_text: Option<String>,
    pub raw_preview: Option<String>,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub index: usize,
    pub endpoint: Endpoint,
    pub status: String,
    pub http: StageInfo,
    pub login: StageInfo,
    pub udp: StageInfo,
    pub sticky: StageInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game_port: Option<u16>,
    pub total_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<SocksTrace>,
}

impl CheckResult {
    pub fn new(index: usize, endpoint: Endpoint) -> Self {
        Self {
            index,
            endpoint,
            status: "PENDING".to_string(),
            http: StageInfo::skipped(),
            login: StageInfo::skipped(),
            udp: StageInfo::skipped(),
            sticky: StageInfo::skipped(),
            http_code: None,
            login_code: None,
            exit_ip: None,
            country: None,
            server: None,
            game_port: None,
            total_ms: 0,
            detail: None,
            trace: None,
        }
    }

    pub fn timeout(index: usize, endpoint: Endpoint, total_ms: u64) -> Self {
        let mut result = Self::new(index, endpoint);
        result.status = "TIMEOUT".to_string();
        result.http = StageInfo::failed("TIMEOUT", total_ms, "total check timeout exceeded");
        result.detail = Some("total check timeout exceeded".to_string());
        result.total_ms = total_ms;
        result
    }

    pub fn is_usable(&self) -> bool {
        self.status == "USABLE"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_endpoint_never_contains_password() {
        let endpoint = Endpoint {
            host: "proxy.example.com".to_string(),
            port: 1080,
            username: "user".to_string(),
            password: "super-secret".to_string(),
        };
        let masked = endpoint.masked();
        assert!(masked.contains("proxy.example.com:1080:user:***"));
        assert!(!masked.contains("super-secret"));
    }

    #[test]
    fn serialized_endpoint_omits_password() {
        let endpoint = Endpoint {
            host: "proxy.example.com".to_string(),
            port: 1080,
            username: "user".to_string(),
            password: "super-secret".to_string(),
        };
        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains("proxy.example.com"));
        assert!(!json.contains("super-secret"));
    }
}
