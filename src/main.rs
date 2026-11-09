#![allow(clippy::result_large_err)]

mod checker;
mod cli;
mod commands;
mod model;
mod output;
mod parser;

use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Fmt(args) => commands::run_fmt(args).await,
        Commands::Check(args) => commands::run_check(args).await,
        Commands::Gen(args) => commands::run_gen(args).await,
        Commands::Test(args) => commands::run_test(args).await,
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(2);
        }
    }
}
