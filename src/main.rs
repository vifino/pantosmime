mod milter_callbacks;
mod mime_parser;
mod smime;

use clap::Parser;
use std::{path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, signal};
use tracing::info;
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
    prelude::*,
};

#[derive(Parser)]
#[command(name = "pantosmime")]
#[command(author = "Adrian 'vifino' Pistol <vifino@posteo.net>")]
#[command(about = "S/MIME Encrypting Milter Daemon", long_about = None)]
#[clap(version)]
struct Cli {
    #[arg(short, long, default_value = "127.0.0.1:22666")]
    listen: String,

    #[arg(short, long)]
    certificate_directory: PathBuf,

    #[arg(short, long, num_args(0..))]
    address: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let listener = TcpListener::bind(cli.listen.clone())
        .await
        .expect("cannot open milter socket");

    info!(cli.listen, "Started listening");

    // TODO: drop privileges, only keep r/w to certificate directory

    let callbacks =
        milter_callbacks::assemble_callbacks(cli.certificate_directory, Arc::new(cli.address));
    let config = Default::default();

    indymilter::run(listener, callbacks, config, signal::ctrl_c())
        .await
        .expect("milter execution failed");
}
