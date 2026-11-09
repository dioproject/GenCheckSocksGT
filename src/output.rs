use crate::checker::CheckOptions;
use crate::model::CheckResult;
use anyhow::{Context, Result};
use chrono::Utc;
use comfy_table::{Cell, Color, Table};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total: usize,
    pub usable: usize,
    pub http_only: usize,
    pub failed: usize,
    pub by_status: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportOptions {
    pub udp: bool,
    pub sticky: bool,
    pub exit_ip: bool,
    pub timeout_secs: u64,
    pub total_timeout_secs: u64,
    pub concurrency: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub generated_at: String,
    pub options: ReportOptions,
    pub summary: Summary,
    pub results: Vec<CheckResult>,
}

pub fn summarize(results: &[CheckResult]) -> Summary {
    let mut by_status = BTreeMap::new();
    for result in results {
        *by_status.entry(result.status.clone()).or_insert(0) += 1;
    }
    let usable = results.iter().filter(|result| result.is_usable()).count();
    let http_only = results
        .iter()
        .filter(|result| result.status == "HTTP_ONLY")
        .count();
    Summary {
        total: results.len(),
        usable,
        http_only,
        failed: results.len().saturating_sub(usable + http_only),
        by_status,
    }
}

pub fn build_report(results: &[CheckResult], options: &CheckOptions, concurrency: usize) -> Report {
    Report {
        generated_at: Utc::now().to_rfc3339(),
        options: ReportOptions {
            udp: options.udp,
            sticky: options.sticky,
            exit_ip: options.exit_ip,
            timeout_secs: options.timeout.as_secs(),
            total_timeout_secs: options.total_timeout.as_secs(),
            concurrency,
        },
        summary: summarize(results),
        results: results.to_vec(),
    }
}

pub fn write_json(path: &Path, report: &Report) -> Result<()> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("failed to create JSON report: {}", path.display()))?;
    serde_json::to_writer_pretty(file, report)
        .with_context(|| format!("failed to write JSON report: {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct CsvRow {
    status: String,
    host: String,
    port: u16,
    username: String,
    http: String,
    http_code: String,
    http_ms: u64,
    login: String,
    login_code: String,
    login_ms: u64,
    udp: String,
    udp_ms: u64,
    sticky: String,
    sticky_ms: u64,
    exit_ip: String,
    country: String,
    server: String,
    game_port: String,
    total_ms: u64,
    detail: String,
}

pub fn write_csv(path: &Path, results: &[CheckResult]) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to create CSV report: {}", path.display()))?;
    for result in results {
        writer.serialize(CsvRow {
            status: result.status.clone(),
            host: result.endpoint.host.clone(),
            port: result.endpoint.port,
            username: result.endpoint.username.clone(),
            http: result.http.status.clone(),
            http_code: option_string(result.http_code.map(|v| v.to_string())),
            http_ms: result.http.ms,
            login: result.login.status.clone(),
            login_code: option_string(result.login_code.map(|v| v.to_string())),
            login_ms: result.login.ms,
            udp: result.udp.status.clone(),
            udp_ms: result.udp.ms,
            sticky: result.sticky.status.clone(),
            sticky_ms: result.sticky.ms,
            exit_ip: option_string(result.exit_ip.clone()),
            country: option_string(result.country.clone()),
            server: option_string(result.server.clone()),
            game_port: option_string(result.game_port.map(|v| v.to_string())),
            total_ms: result.total_ms,
            detail: option_string(result.detail.clone()),
        })?;
    }
    writer.flush().context("failed to flush CSV report")?;
    Ok(())
}

fn option_string(value: Option<String>) -> String {
    value.unwrap_or_default()
}

pub fn print_table(results: &[CheckResult]) {
    let mut table = Table::new();
    table.load_preset(comfy_table::presets::UTF8_FULL);
    table.set_header(vec![
        "#", "Status", "Endpoint", "HTTP", "UDP", "Sticky", "Exit IP", "Total",
    ]);

    for (row, result) in results.iter().enumerate() {
        let endpoint = result.endpoint.masked();
        let exit_ip = match (&result.exit_ip, &result.country) {
            (Some(ip), Some(country)) => format!("{ip} ({country})"),
            (Some(ip), None) => ip.clone(),
            _ => "-".to_string(),
        };
        table.add_row(vec![
            Cell::new(row + 1),
            status_cell(&result.status),
            Cell::new(endpoint),
            stage_cell(&result.http),
            stage_cell(&result.udp),
            stage_cell(&result.sticky),
            Cell::new(exit_ip),
            Cell::new(format!("{}ms", result.total_ms)),
        ]);
    }

    println!("{table}");
    print_summary(&summarize(results));
}

pub fn print_summary(summary: &Summary) {
    println!(
        "Total: {} | Usable: {} | HTTP only: {} | Failed: {}",
        summary.total, summary.usable, summary.http_only, summary.failed
    );
    if !summary.by_status.is_empty() {
        let counts = summary
            .by_status
            .iter()
            .map(|(status, count)| format!("{status}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Statuses: {counts}");
    }
}

fn status_cell(status: &str) -> Cell {
    let color = match status {
        "USABLE" => Color::Green,
        "HTTP_ONLY" => Color::Yellow,
        "BLOCKED" => Color::Red,
        _ => Color::Red,
    };
    Cell::new(status).fg(color)
}

fn stage_cell(stage: &crate::model::StageInfo) -> Cell {
    let text = if stage.status == "SKIPPED" {
        "SKIPPED".to_string()
    } else {
        format!("{} {}ms", stage.status, stage.ms)
    };
    let color = match stage.status.as_str() {
        "OK" => Color::Green,
        "SKIPPED" => Color::DarkGrey,
        "UNSUPPORTED" | "ROTATING" | "UNKNOWN" => Color::Yellow,
        _ => Color::Red,
    };
    Cell::new(text).fg(color)
}
