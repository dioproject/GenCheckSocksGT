use crate::checker::{self, CheckOptions};
use crate::cli::{CheckArgs, CommonCheckArgs, FmtArgs, GenArgs, OutputFormat, TestArgs};
use crate::model::{CheckResult, StageInfo};
use crate::output;
use crate::parser;
use anyhow::{Context, Result, anyhow, bail};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use std::time::Duration;

pub async fn run_fmt(args: FmtArgs) -> Result<i32> {
    let loaded = load_input(&args.input, !args.no_unique, args.strict)?;
    let lines: Vec<String> = loaded
        .endpoints
        .iter()
        .map(|endpoint| match args.format {
            OutputFormat::Colon => endpoint.to_colon(),
            OutputFormat::Pipe => endpoint.to_pipe(),
        })
        .collect();

    write_lines(args.out.as_deref(), &lines)?;
    let destination = match args.out.as_deref() {
        Some(path) if path != Path::new("-") => path.display().to_string(),
        _ => "stdout".to_string(),
    };
    eprintln!("Normalized {} endpoint(s) to {}", lines.len(), destination);
    Ok(0)
}

pub async fn run_check(args: CheckArgs) -> Result<i32> {
    let loaded = load_input(&args.input, true, false)?;
    let options = build_options(&args.common, false, false);
    let total = loaded.endpoints.len();
    let progress = make_progress(total, args.common.quiet);
    let results = checker::check_all(
        loaded.endpoints,
        options.clone(),
        args.common.concurrency,
        progress.clone(),
    )
    .await;
    if let Some(progress) = progress {
        progress.finish_and_clear();
    }

    output::print_table(&results);

    if let Some(path) = &args.out {
        ensure_parent(path)?;
        let report = output::build_report(&results, &options, args.common.concurrency);
        output::write_json(path, &report)?;
        eprintln!("JSON report: {}", path.display());
    }
    if let Some(path) = &args.csv {
        ensure_parent(path)?;
        output::write_csv(path, &results)?;
        eprintln!("CSV report: {}", path.display());
    }

    Ok(if results.iter().any(CheckResult::is_usable) {
        0
    } else {
        1
    })
}

pub async fn run_gen(args: GenArgs) -> Result<i32> {
    let loaded = load_input(&args.input, true, false)?;
    let options = build_options(&args.common, args.allow_no_udp, args.allow_rotating);
    let total = loaded.endpoints.len();
    let progress = make_progress(total, args.common.quiet);
    let results = checker::check_all(
        loaded.endpoints,
        options.clone(),
        args.common.concurrency,
        progress.clone(),
    )
    .await;
    if let Some(progress) = progress {
        progress.finish_and_clear();
    }

    let mut usable: Vec<&CheckResult> =
        results.iter().filter(|result| result.is_usable()).collect();
    usable.sort_by_key(|result| (result.total_ms, result.index));
    if let Some(top) = args.top {
        usable.truncate(top);
    }

    let lines: Vec<String> = usable
        .iter()
        .map(|result| match args.format {
            OutputFormat::Colon => result.endpoint.to_colon(),
            OutputFormat::Pipe => result.endpoint.to_pipe(),
        })
        .collect();

    write_lines(Some(args.out.as_path()), &lines)?;

    if args.out != Path::new("-") && !usable.is_empty() {
        println!(
            "Usable proxies (passwords masked; full lines in {}):",
            args.out.display()
        );
        for (position, result) in usable.iter().enumerate() {
            let exit = match (&result.exit_ip, &result.country) {
                (Some(ip), Some(country)) => format!("{ip} ({country})"),
                (Some(ip), None) => ip.clone(),
                _ => "-".to_string(),
            };
            println!(
                "  {:>3}. {:<52} exit={:<20} {}ms",
                position + 1,
                result.endpoint.masked(),
                exit,
                result.total_ms
            );
        }
        println!();
    }

    let summary = output::summarize(&results);
    eprintln!(
        "Checked {} endpoint(s): {} usable, {} HTTP-only, {} failed",
        summary.total, summary.usable, summary.http_only, summary.failed
    );
    if lines.is_empty() {
        eprintln!("No usable proxy matched the current filters.");
    } else {
        let destination = if args.out == Path::new("-") {
            "stdout".to_string()
        } else {
            args.out.display().to_string()
        };
        eprintln!(
            "Wrote {} usable endpoint(s) to {} (plaintext credentials)",
            lines.len(),
            destination
        );
    }

    if let Some(path) = &args.details {
        ensure_parent(path)?;
        let report = output::build_report(&results, &options, args.common.concurrency);
        output::write_json(path, &report)?;
        eprintln!("Detailed JSON report: {}", path.display());
    }

    Ok(if lines.is_empty() { 1 } else { 0 })
}

pub async fn run_test(args: TestArgs) -> Result<i32> {
    let endpoint =
        parser::parse_endpoint(&args.proxy).map_err(|error| anyhow!("invalid proxy: {error}"))?;
    let mut options = build_options(&args.common, false, false);
    // A single-proxy test should always carry the protocol trace.
    options.trace = true;

    let result = checker::check_one_timeout(0, endpoint, options).await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_test_result(&result);
    }

    Ok(if result.is_usable() { 0 } else { 1 })
}

fn load_input(input: &str, dedup: bool, strict: bool) -> Result<parser::LoadResult> {
    let loaded = parser::load_endpoints(input, dedup)?;

    if !loaded.issues.is_empty() {
        eprintln!(
            "warning: {} invalid input line(s) skipped",
            loaded.issues.len()
        );
        for issue in loaded.issues.iter().take(10) {
            eprintln!("  line {}: {}  [{}]", issue.line, issue.reason, issue.raw);
        }
        if loaded.issues.len() > 10 {
            eprintln!("  ... and {} more", loaded.issues.len() - 10);
        }
        if strict {
            bail!("invalid input lines present (--strict)");
        }
    }
    if loaded.duplicates > 0 {
        eprintln!("note: removed {} duplicate endpoint(s)", loaded.duplicates);
    }
    if loaded.endpoints.is_empty() {
        bail!("no valid SOCKS5 endpoints found");
    }
    Ok(loaded)
}

fn build_options(
    common: &CommonCheckArgs,
    allow_no_udp: bool,
    allow_rotating: bool,
) -> CheckOptions {
    let timeout = Duration::from_secs(common.timeout.max(1));
    let total_timeout = Duration::from_secs(common.total_timeout.max(timeout.as_secs()));
    let mut sticky = !common.fast && !common.skip_sticky && !allow_rotating;
    let mut exit_ip = !common.fast && !common.skip_exit_ip;
    if common.skip_exit_ip {
        sticky = false;
    }
    if sticky {
        exit_ip = true;
    }
    let udp = !common.fast && !common.skip_udp && !allow_no_udp;

    CheckOptions {
        timeout,
        total_timeout,
        udp,
        sticky,
        exit_ip,
        trace: common.trace,
    }
}

fn make_progress(total: usize, quiet: bool) -> Option<ProgressBar> {
    if quiet || total == 0 {
        return None;
    }
    let progress = ProgressBar::new(total as u64);
    let style = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
    )
    .expect("valid progress template")
    .progress_chars("#>-");
    progress.set_style(style);
    progress.set_message("checking");
    Some(progress)
}

fn write_lines(out: Option<&Path>, lines: &[String]) -> Result<()> {
    let content = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };

    match out {
        Some(path) if path != Path::new("-") => {
            ensure_parent(path)?;
            std::fs::write(path, content)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }
        _ => print!("{content}"),
    }
    Ok(())
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    Ok(())
}

fn print_test_result(result: &CheckResult) {
    println!("Endpoint : {}", result.endpoint.masked());
    println!("Status   : {}", result.status);
    println!("HTTP     : {}", format_stage(&result.http));
    if let Some(code) = result.http_code {
        println!("HTTP code: {code}");
    }
    println!("Login    : {}", format_stage(&result.login));
    if let Some(code) = result.login_code {
        println!("Login code: {code}");
    }
    println!("UDP      : {}", format_stage(&result.udp));
    println!("Sticky   : {}", format_stage(&result.sticky));
    if let Some(exit_ip) = &result.exit_ip {
        match &result.country {
            Some(country) => println!("Exit IP  : {exit_ip} ({country})"),
            None => println!("Exit IP  : {exit_ip}"),
        }
    }
    if let (Some(server), Some(port)) = (&result.server, result.game_port) {
        println!("Game     : {server}:{port}");
    }
    println!("Total    : {}ms", result.total_ms);
    if let Some(detail) = &result.detail {
        println!("Detail   : {detail}");
    }

    match &result.trace {
        Some(trace) => {
            println!("\nSOCKS5 trace:");
            if let Some(ip) = &trace.proxy_resolved {
                println!("  proxy IP        : {ip}");
            }
            println!("  target          : {} via {}", trace.target, trace.command);
            println!(
                "  timings         : tcp={}ms greeting={}ms auth={}ms connect={}ms",
                trace.tcp_ms, trace.greeting_ms, trace.auth_ms, trace.connect_ms
            );
            println!("  greeting sent   : {}", trace.greeting_sent);
            println!("  greeting recv   : {}", trace.greeting_recv);
            if let Some(method) = trace.method {
                println!("  auth method     : 0x{method:02x}");
            }
            if let Some(status) = trace.auth_status {
                println!("  auth status     : 0x{status:02x}");
            }
            if let Some(code) = trace.reply_code {
                println!(
                    "  reply           : 0x{code:02x} ({})",
                    trace.reply_text.as_deref().unwrap_or("")
                );
            }
            if let Some(preview) = &trace.raw_preview {
                println!("  raw preview     : {preview}");
            }
            if !trace.events.is_empty() {
                println!("  events:");
                for event in &trace.events {
                    println!("    - {event}");
                }
            }
        }
        None => println!("\nSOCKS5 trace: not captured"),
    }
}

fn format_stage(stage: &StageInfo) -> String {
    match &stage.error {
        Some(error) => format!("{} ({}ms) - {error}", stage.status, stage.ms),
        None if stage.status == "SKIPPED" => "SKIPPED".to_string(),
        None => format!("{} ({}ms)", stage.status, stage.ms),
    }
}
