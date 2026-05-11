// FILE: src/main.rs
// PURPOSE: Gannet CLI entry point
#![allow(dead_code)]
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod cli;
mod discovery;
mod identity;
mod net;

#[derive(Parser)]
#[command(name = "gannet")]
#[command(about = "Network device discovery and fingerprinting")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(short, long)]
        subnet: Option<String>,
        #[arg(short, long)]
        interface: Option<String>,
        #[arg(short, long)]
        verbose: bool,
        #[arg(long, default_value = ".gannet/devices.json")]
        store: PathBuf,
    },
    Tag {
        ip: String,
        tag: String,
        #[arg(long, default_value = ".gannet/devices.json")]
        store: PathBuf,
    },
    List {
        #[arg(long, default_value = ".gannet/devices.json")]
        store: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { subnet, interface, verbose, store } => {
            cli::commands::scan(subnet, interface, verbose, store).await;
        }
        Commands::Tag { ip, tag, store } => {
            cli::commands::tag(ip, tag, store);
        }
        Commands::List { store } => {
            cli::commands::list(store);
        }
    }
}