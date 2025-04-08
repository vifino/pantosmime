mod milter_callbacks;
mod mime_parser;
mod smime;

use clap::Parser;
use std::{path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, signal};

#[derive(Parser)]
#[command(name = "pantosmime")]
#[command(author = "Adrian 'vifino' Pistol <vifino@posteo.net>")]
#[command(about = "S/MIME Encrypting Milter Daemon", long_about = None)]
#[clap(version)]
struct Cli {
    #[arg(default_value = "127.0.0.1:22666")]
    listen: String,

    certificate_directory: PathBuf,

    #[arg(num_args(0..))]
    address: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let listener = TcpListener::bind(cli.listen)
        .await
        .expect("cannot open milter socket");

    let callbacks =
        milter_callbacks::assemble_callbacks(cli.certificate_directory, Arc::new(cli.address));
    let config = Default::default();

    indymilter::run(listener, callbacks, config, signal::ctrl_c())
        .await
        .expect("milter execution failed");
}
