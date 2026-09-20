mod limited;

use crate::config::Config;
use crate::http::App;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use limited::LimitedTcp;
use rustls_acme::AcmeConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::futures_rustls::rustls::{ClientConfig, RootCertStore};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_stream::StreamExt;

const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("cache setup failed: {0}")]
    Cache(#[source] std::io::Error),
    #[error("ACME CA certificate failed: {0}")]
    Certificate(#[source] std::io::Error),
    #[error("ACME CA certificate is invalid")]
    InvalidCertificate,
    #[error("TLS client configuration failed: {0}")]
    Tls(String),
    #[error("listener failed: {0}")]
    Listener(#[source] std::io::Error),
}

pub async fn serve(config: &Config, app: Arc<App>) -> Result<(), ServerError> {
    prepare_cache(&config.acme_cache_dir)?;
    let client = acme_client(config)?;
    let directory = match config.acme_directory.as_str() {
        "production" => LETS_ENCRYPT_PRODUCTION,
        "staging" => LETS_ENCRYPT_STAGING,
        other => other,
    };
    let acme = client.map_or_else(
        || AcmeConfig::new([config.acme_domain.clone()]),
        |client| AcmeConfig::new_with_client_config([config.acme_domain.clone()], client),
    );
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(ServerError::Listener)?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let incoming = futures::stream::unfold((listener, permits), |(listener, permits)| async move {
        let permit = permits.clone().acquire_owned().await.ok()?;
        let accepted = listener
            .accept()
            .await
            .map(|(stream, address)| LimitedTcp::new(stream, address.ip(), permit));
        Some((accepted, (listener, permits)))
    });
    let mut tls = acme
        .contact([config.acme_contact.clone()])
        .cache(DirCache::new(config.acme_cache_dir.clone()))
        .directory(directory)
        .tokio_incoming(Box::pin(incoming), Vec::new());

    tracing::info!(listen = %config.listen, domain = %config.acme_domain, "HTTPS update service started");
    while let Some(connection) = tls.next().await {
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = ?error, "TLS or ACME connection failed");
                continue;
            }
        };
        let peer = connection.get_ref().get_ref().0.get_ref().peer();
        let app = Arc::clone(&app);
        tokio::spawn(async move {
            let service = service_fn(move |request| Arc::clone(&app).handle(peer, request));
            let mut http = http1::Builder::new();
            http.keep_alive(false)
                .max_headers(32)
                .max_buf_size(8192)
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            if let Err(error) = http
                .serve_connection(TokioIo::new(connection), service)
                .await
            {
                tracing::debug!(error = %error, "HTTPS connection closed");
            }
        });
    }
    Err(ServerError::Listener(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "TLS listener ended",
    )))
}

fn acme_client(config: &Config) -> Result<Option<Arc<ClientConfig>>, ServerError> {
    let Some(path) = &config.acme_ca_certificate else {
        return Ok(None);
    };
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut reader = BufReader::new(File::open(path).map_err(ServerError::Certificate)?);
    let mut added = 0_u32;
    for certificate in rustls_pemfile::certs(&mut reader) {
        let certificate = certificate.map_err(ServerError::Certificate)?;
        roots
            .add(certificate)
            .map_err(|_| ServerError::InvalidCertificate)?;
        added += 1;
    }
    if added == 0 {
        return Err(ServerError::InvalidCertificate);
    }
    let provider = rustls_acme::futures_rustls::rustls::crypto::ring::default_provider();
    let client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| ServerError::Tls(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Some(Arc::new(client)))
}

fn prepare_cache(path: &Path) -> Result<(), ServerError> {
    std::fs::create_dir_all(path).map_err(ServerError::Cache)?;
    let metadata = std::fs::symlink_metadata(path).map_err(ServerError::Cache)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ServerError::Cache(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ACME cache is not a regular directory",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(ServerError::Cache)?;
    }
    Ok(())
}
