mod acme;

use acme::validate_directory;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub acme_domain: String,
    pub acme_contact: String,
    #[serde(default = "production")]
    pub acme_directory: String,
    pub acme_cache_dir: PathBuf,
    #[serde(default)]
    pub acme_ca_certificate: Option<PathBuf>,
    pub dns_server: SocketAddr,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default = "default_timeout")]
    pub request_timeout_seconds: u64,
    #[serde(default = "default_global_rate")]
    pub global_requests_per_minute: u32,
    #[serde(default = "default_host_rate")]
    pub per_host_updates_per_minute: u32,
    #[serde(default = "default_peer_rate")]
    pub unauthenticated_requests_per_peer_per_minute: u32,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    pub hosts: Vec<Host>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub hostname: String,
    pub zone: String,
    pub username: String,
    #[serde(default = "yes")]
    pub allow_ipv4: bool,
    #[serde(default = "yes")]
    pub allow_ipv6: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    pub tsig: Tsig,
    pub credentials: Vec<Credential>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tsig {
    pub key_name: String,
    pub secret_base64: String,
    #[serde(default)]
    pub algorithm: TsigAlgorithm,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    #[default]
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid TOML in {path}: {source}")]
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = read(path)?;
        let value: Self = toml::from_str(&text).map_err(|source| ConfigError::Toml {
            path: path.to_path_buf(),
            source,
        })?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        dns_name(&self.acme_domain)?;
        if !self.acme_contact.starts_with("mailto:") || self.acme_contact.len() <= 7 {
            return invalid("acme_contact must be a non-empty mailto: URI");
        }
        validate_directory(&self.acme_directory)?;
        absolute_runtime_dir(&self.acme_cache_dir, "acme_cache_dir")?;
        if let Some(path) = &self.acme_ca_certificate
            && !path.is_absolute()
        {
            return invalid("acme_ca_certificate must be absolute");
        }
        if self.ttl == 0 || self.request_timeout_seconds == 0 {
            return invalid("ttl and request_timeout_seconds must be non-zero");
        }
        if self.global_requests_per_minute == 0
            || self.per_host_updates_per_minute == 0
            || self.unauthenticated_requests_per_peer_per_minute == 0
        {
            return invalid("rate limits must be non-zero");
        }
        if !(1..=4096).contains(&self.max_connections) {
            return invalid("max_connections must be between 1 and 4096");
        }
        if self.hosts.is_empty() {
            return invalid("at least one host is required");
        }
        let mut names = HashSet::new();
        let mut usernames = HashSet::new();
        for host in &self.hosts {
            let name = canonical_name(&host.hostname)?;
            let zone = canonical_name(&host.zone)?;
            if name != zone && !name.ends_with(&format!(".{zone}")) {
                return invalid(format!("{} is outside zone {}", host.hostname, host.zone));
            }
            if host.username.is_empty() {
                return invalid("host username must not be empty");
            }
            if !usernames.insert(host.username.as_str()) {
                return invalid("each host must have a unique username");
            }
            if !host.allow_ipv4 && !host.allow_ipv6 {
                return invalid(format!("{} allows no address family", host.hostname));
            }
            if !names.insert(name) {
                return invalid("hostnames must be unique");
            }
        }
        Ok(())
    }
}

impl Secrets {
    pub fn load(path: &Path, config: &Config) -> Result<Self, ConfigError> {
        validate_secret_file(path)?;
        let text = read(path)?;
        let value: Self = toml::from_str(&text).map_err(|source| ConfigError::Toml {
            path: path.to_path_buf(),
            source,
        })?;
        value.validate(config)?;
        Ok(value)
    }

    fn validate(&self, config: &Config) -> Result<(), ConfigError> {
        dns_name(&self.tsig.key_name)?;
        if self.tsig.secret_base64.is_empty() {
            return invalid("TSIG secret must not be empty");
        }
        let mut users = HashSet::new();
        for credential in &self.credentials {
            if credential.username.is_empty() || credential.password.is_empty() {
                return invalid("credential fields must not be empty");
            }
            if !users.insert(credential.username.as_str()) {
                return invalid("credential usernames must be unique");
            }
        }
        for host in &config.hosts {
            if !users.contains(host.username.as_str()) {
                return invalid(format!("missing credential for {}", host.username));
            }
        }
        if users
            .iter()
            .any(|user| !config.hosts.iter().any(|h| h.username == **user))
        {
            return invalid("credential exists without a configured host");
        }
        Ok(())
    }
}

pub fn canonical_name(value: &str) -> Result<String, ConfigError> {
    let name = value.trim_end_matches('.').to_ascii_lowercase();
    dns_name(&name)?;
    Ok(name)
}

fn dns_name(value: &str) -> Result<(), ConfigError> {
    let value = value.trim_end_matches('.');
    if value.is_empty() || value.len() > 253 {
        return invalid("invalid DNS name length");
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return invalid(format!("invalid DNS name: {value}"));
        }
    }
    Ok(())
}

fn absolute_runtime_dir(path: &Path, field: &str) -> Result<(), ConfigError> {
    if !path.is_absolute() || path.starts_with("/nix/store") {
        return invalid(format!(
            "{field} must be an absolute path outside /nix/store"
        ));
    }
    Ok(())
}

fn validate_secret_file(path: &Path) -> Result<(), ConfigError> {
    absolute_runtime_dir(path, "secrets path")?;
    let metadata = std::fs::symlink_metadata(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return invalid("secrets path must be a regular, non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o7177 != 0 {
            return invalid(
                "secrets file must be private, non-executable, and have no special mode bits",
            );
        }
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })
}
fn invalid<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(message.into()))
}
fn production() -> String {
    "production".into()
}
const fn default_ttl() -> u32 {
    300
}
const fn default_timeout() -> u64 {
    10
}
const fn default_global_rate() -> u32 {
    120
}
const fn default_host_rate() -> u32 {
    6
}
const fn default_peer_rate() -> u32 {
    30
}
const fn default_max_connections() -> usize {
    128
}
const fn yes() -> bool {
    true
}
