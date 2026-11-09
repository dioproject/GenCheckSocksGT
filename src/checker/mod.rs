pub mod http;
pub mod socks5;
pub mod udp;

use crate::model::{CheckResult, Endpoint, SocksTrace, StageInfo};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Debug, Clone)]
pub struct CheckOptions {
    /// Per-operation timeout (SOCKS connect, TLS handshake, HTTP request, UDP probe).
    pub timeout: Duration,
    /// Hard cap for one endpoint, across all stages.
    pub total_timeout: Duration,
    pub udp: bool,
    pub sticky: bool,
    pub exit_ip: bool,
    pub trace: bool,
}

#[derive(Debug, Clone)]
pub struct StageError {
    pub status: String,
    pub message: String,
    pub trace: Option<SocksTrace>,
}

impl StageError {
    pub fn new(status: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            message: message.into(),
            trace: None,
        }
    }

    pub fn with_trace(mut self, trace: Option<SocksTrace>) -> Self {
        self.trace = trace;
        self
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new("TIMEOUT", message)
    }

    pub fn from_socks(error: socks5::SocksError) -> Self {
        Self {
            status: error.status.to_string(),
            message: error.message,
            trace: Some(error.trace),
        }
    }
}

pub async fn check_one_timeout(
    index: usize,
    endpoint: Endpoint,
    options: CheckOptions,
) -> CheckResult {
    let total_timeout = options.total_timeout;
    match tokio::time::timeout(total_timeout, check_one(index, endpoint.clone(), options)).await {
        Ok(result) => result,
        Err(_) => CheckResult::timeout(
            index,
            endpoint,
            total_timeout.as_millis().min(u64::MAX as u128) as u64,
        ),
    }
}

pub async fn check_all(
    endpoints: Vec<Endpoint>,
    options: CheckOptions,
    concurrency: usize,
    progress: Option<indicatif::ProgressBar>,
) -> Vec<CheckResult> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for (index, endpoint) in endpoints.into_iter().enumerate() {
        let semaphore = semaphore.clone();
        let options = options.clone();
        tasks.spawn(async move {
            let permit = semaphore
                .acquire_owned()
                .await
                .expect("checker semaphore was closed");
            let result = check_one_timeout(index, endpoint, options).await;
            drop(permit);
            result
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(result) => results.push(result),
            Err(error) => eprintln!("warning: checker task failed: {error}"),
        }
        if let Some(progress) = &progress {
            progress.inc(1);
        }
    }

    results.sort_by_key(|result| result.index);
    results
}

pub async fn check_one(index: usize, endpoint: Endpoint, options: CheckOptions) -> CheckResult {
    let started = Instant::now();
    let mut result = CheckResult::new(index, endpoint.clone());
    let mut details = Vec::new();

    // Stage 1: Growtopia server_data.php. If this fails, the proxy is not
    // useful for the game and there is no point spending time on UDP/sticky.
    let http_started = Instant::now();
    match http::fetch_server_data(&endpoint, options.timeout).await {
        Ok(data) => {
            result.http = StageInfo::ok(elapsed_ms(http_started));
            result.http_code = Some(data.status);
            result.server = Some(data.server.clone());
            result.game_port = Some(data.port);
            if options.trace {
                result.trace = data.trace;
            }
            if data.meta.is_none() {
                details.push("server_data.php did not return a meta field".to_string());
            }
            if data.login_url != "login.growtopiagame.com" {
                details.push(format!("server_data loginurl={}", data.login_url));
            }
        }
        Err(error) => {
            result.http = StageInfo::failed(
                error.status.clone(),
                elapsed_ms(http_started),
                error.message.clone(),
            );
            result.status = error.status;
            result.detail = Some(error.message);
            if options.trace {
                result.trace = error.trace;
            }
            result.total_ms = elapsed_ms(started);
            return result;
        }
    }

    // Stage 2: the login host. A proxy can reach server_data.php and still be
    // rejected by login.growtopiagame.com.
    let login_started = Instant::now();
    match http::check_login(&endpoint, options.timeout).await {
        Ok(code) => {
            result.login = StageInfo::ok(elapsed_ms(login_started));
            result.login_code = Some(code);
        }
        Err(error) => {
            result.login = StageInfo::failed(
                error.status.clone(),
                elapsed_ms(login_started),
                error.message.clone(),
            );
            result.status = error.status;
            result.detail = Some(error.message);
            if options.trace {
                result.trace = error.trace;
            }
            result.total_ms = elapsed_ms(started);
            return result;
        }
    }

    // Stage 3: SOCKS5 UDP ASSOCIATE + a real DNS round trip through the relay.
    if options.udp {
        let udp_started = Instant::now();
        match udp::check(&endpoint, options.timeout).await {
            Ok(()) => result.udp = StageInfo::ok(elapsed_ms(udp_started)),
            Err(error) => {
                result.udp = StageInfo::failed(
                    error.status.clone(),
                    elapsed_ms(udp_started),
                    error.message.clone(),
                );
                details.push(format!(
                    "UDP {}: {}",
                    error.status.to_ascii_lowercase(),
                    error.message
                ));
                if options.trace {
                    result.trace = error.trace;
                }
            }
        }
    } else {
        result.udp = StageInfo::skipped();
    }

    // Stage 4: exit IP, optionally twice to verify the exit is sticky.
    if options.sticky || options.exit_ip {
        let exit_started = Instant::now();
        match http::fetch_exit_info(&endpoint, options.timeout).await {
            Ok(first) => {
                result.exit_ip = Some(first.ip.clone());
                result.country = first.country.clone();
                if options.sticky {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    match http::fetch_exit_info(&endpoint, options.timeout).await {
                        Ok(second) => {
                            if first.ip == second.ip {
                                result.sticky = StageInfo::ok(elapsed_ms(exit_started));
                            } else {
                                let message =
                                    format!("exit IP changed: {} -> {}", first.ip, second.ip);
                                result.sticky = StageInfo::failed(
                                    "ROTATING",
                                    elapsed_ms(exit_started),
                                    message.clone(),
                                );
                                details.push(message);
                            }
                        }
                        Err(error) => {
                            result.sticky = StageInfo::failed(
                                "UNKNOWN",
                                elapsed_ms(exit_started),
                                error.message.clone(),
                            );
                            details.push(format!("sticky check failed: {}", error.message));
                            if options.trace {
                                result.trace = error.trace;
                            }
                        }
                    }
                } else {
                    result.sticky = StageInfo::skipped();
                }
            }
            Err(error) => {
                if options.sticky {
                    result.sticky = StageInfo::failed(
                        "UNKNOWN",
                        elapsed_ms(exit_started),
                        error.message.clone(),
                    );
                    details.push(format!("exit IP check failed: {}", error.message));
                    if options.trace {
                        result.trace = error.trace;
                    }
                } else {
                    result.sticky = StageInfo::skipped();
                    details.push(format!("exit IP check failed: {}", error.message));
                }
            }
        }
    } else {
        result.sticky = StageInfo::skipped();
    }

    if (options.udp && !result.udp.is_ok()) || (options.sticky && !result.sticky.is_ok()) {
        result.status = "HTTP_ONLY".to_string();
    } else {
        result.status = "USABLE".to_string();
    }

    result.detail = if details.is_empty() {
        None
    } else {
        Some(details.join("; "))
    };
    result.total_ms = elapsed_ms(started);
    result
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}
