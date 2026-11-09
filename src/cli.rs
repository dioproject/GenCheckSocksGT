use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "gencheck",
    version,
    about = "SOCKS5 checker and working-proxy list generator for Growtopia",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Normalize and deduplicate a proxy list.
    Fmt(FmtArgs),
    /// Check every proxy and print a detailed table.
    Check(CheckArgs),
    /// Generate a working.txt file containing only usable proxies.
    Gen(GenArgs),
    /// Check one proxy with a detailed SOCKS5 trace.
    Test(TestArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Colon,
    Pipe,
}

#[derive(Debug, Args)]
pub struct FmtArgs {
    /// Input file, or - for stdin.
    #[arg(short, long, default_value = "-")]
    pub input: String,

    /// Output file, or - for stdout.
    #[arg(short, long)]
    pub out: Option<PathBuf>,

    /// Output list format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Colon)]
    pub format: OutputFormat,

    /// Keep duplicate endpoints.
    #[arg(long)]
    pub no_unique: bool,

    /// Treat invalid input lines as fatal errors.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, Args, Clone)]
pub struct CommonCheckArgs {
    /// Per-operation timeout in seconds.
    #[arg(long, default_value_t = 15)]
    pub timeout: u64,

    /// Hard timeout for one endpoint in seconds.
    #[arg(long, default_value_t = 120)]
    pub total_timeout: u64,

    /// Number of proxies checked in parallel.
    #[arg(long, default_value_t = 16)]
    pub concurrency: usize,

    /// Skip the SOCKS5 UDP ASSOCIATE test.
    #[arg(long)]
    pub skip_udp: bool,

    /// Skip the sticky exit-IP test.
    #[arg(long)]
    pub skip_sticky: bool,

    /// Skip the exit-IP lookup (also disables sticky testing).
    #[arg(long)]
    pub skip_exit_ip: bool,

    /// HTTP + login only. Equivalent to --skip-udp --skip-sticky --skip-exit-ip.
    #[arg(long)]
    pub fast: bool,

    /// Include the SOCKS5 protocol trace in JSON output.
    #[arg(long)]
    pub trace: bool,

    /// Suppress the progress bar.
    #[arg(long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Input file, or - for stdin.
    #[arg(short, long, default_value = "-")]
    pub input: String,

    /// Write a JSON report to this file.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Write a CSV report to this file.
    #[arg(long)]
    pub csv: Option<PathBuf>,

    #[command(flatten)]
    pub common: CommonCheckArgs,
}

#[derive(Debug, Args)]
pub struct GenArgs {
    /// Input file, or - for stdin.
    #[arg(short, long, default_value = "-")]
    pub input: String,

    /// Output file containing usable proxies.
    #[arg(short, long, default_value = "working.txt")]
    pub out: PathBuf,

    /// Output list format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Colon)]
    pub format: OutputFormat,

    /// Keep only the N fastest usable proxies.
    #[arg(long)]
    pub top: Option<usize>,

    /// Also write the full JSON report to this file.
    #[arg(long)]
    pub details: Option<PathBuf>,

    /// Accept proxies without UDP support.
    #[arg(long)]
    pub allow_no_udp: bool,

    /// Accept proxies whose exit IP changes between requests.
    #[arg(long)]
    pub allow_rotating: bool,

    #[command(flatten)]
    pub common: CommonCheckArgs,
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// Endpoint in any supported input format.
    pub proxy: String,

    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,

    #[command(flatten)]
    pub common: CommonCheckArgs,
}
