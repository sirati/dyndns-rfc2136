#![forbid(unsafe_code)]

use clap::Parser;
use dyndns_rfc2136::auth::AuthDb;
use dyndns_rfc2136::config::{Config, Secrets};
use dyndns_rfc2136::dns::Rfc2136Writer;
use dyndns_rfc2136::http::App;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    secrets: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();
    let arguments = Arguments::parse();
    let config = Config::load(&arguments.config)?;
    let secrets = Secrets::load(&arguments.secrets, &config)?;
    let auth = AuthDb::new(&secrets.credentials);
    let dns = Rfc2136Writer::new(config.dns_server, &secrets.tsig, config.ttl)?;
    let app = Arc::new(App::new(&config, auth, dns)?);
    drop(secrets);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = dyndns_rfc2136::tls::serve(&config, app) => result?,
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {}
    }
    Ok(())
}
