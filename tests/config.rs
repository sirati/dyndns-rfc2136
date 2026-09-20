#![allow(clippy::unwrap_used)]

use dyndns_rfc2136::config::{Config, Secrets};
use std::fs;
use std::os::unix::fs::PermissionsExt;

const PUBLIC: &str = r#"
listen = "[::]:443"
acme_domain = "dyndns.example.org"
acme_contact = "mailto:admin@example.org"
acme_directory = "staging"
acme_cache_dir = "/var/lib/dyndns-rfc2136/acme"
dns_server = "192.0.2.53:53"

[[hosts]]
hostname = "home.example.org"
zone = "example.org"
username = "router"
allow_ipv4 = true
allow_ipv6 = true
"#;

const PRIVATE: &str = r#"
[tsig]
key_name = "dyndns-key.example.org"
secret_base64 = "c2VjcmV0"
algorithm = "hmac-sha256"

[[credentials]]
username = "router"
password = "long-secret"
"#;

#[test]
fn loads_split_public_and_private_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let public = directory.path().join("public.toml");
    let private = directory.path().join("private.toml");
    fs::write(&public, PUBLIC).unwrap();
    fs::write(&private, PRIVATE).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    let config = Config::load(&public).unwrap();
    let secrets = Secrets::load(&private, &config).unwrap();
    assert_eq!(config.hosts.len(), 1);
    assert_eq!(secrets.credentials.len(), 1);
}

#[test]
fn rejects_world_readable_secret_file() {
    let directory = tempfile::tempdir().unwrap();
    let public = directory.path().join("public.toml");
    let private = directory.path().join("private.toml");
    fs::write(&public, PUBLIC).unwrap();
    fs::write(&private, PRIVATE).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
    let config = Config::load(&public).unwrap();
    assert!(Secrets::load(&private, &config).is_err());
}

#[test]
fn validates_acme_and_owner_boundaries() {
    let invalid = PUBLIC.replace(
        "acme_directory = \"staging\"",
        "acme_directory = \"ftp://ca.example.org/dir\"",
    );
    let config: Config = toml::from_str(&invalid).unwrap();
    assert!(config.validate().is_err());

    let invalid = PUBLIC.replace(
        "acme_directory = \"staging\"",
        "acme_directory = \"http://ca.example.org/dir\"",
    );
    let config: Config = toml::from_str(&invalid).unwrap();
    assert!(config.validate().is_err());

    let invalid = PUBLIC.replace("zone = \"example.org\"", "zone = \"other.example\"");
    let config: Config = toml::from_str(&invalid).unwrap();
    assert!(config.validate().is_err());

    let duplicate_username = format!(
        "{PUBLIC}\n[[hosts]]\nhostname = \"other.example.org\"\nzone = \"example.org\"\nusername = \"router\"\n"
    );
    let config: Config = toml::from_str(&duplicate_username).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn accepts_custom_acme_directory_and_test_ca() {
    let custom = PUBLIC
        .replace(
            "acme_directory = \"staging\"",
            "acme_directory = \"https://127.0.0.1:14000/dir\"",
        )
        .replace(
            "dns_server =",
            "acme_ca_certificate = \"/etc/pebble/ca.pem\"\ndns_server =",
        );
    let config: Config = toml::from_str(&custom).unwrap();
    config.validate().unwrap();
}
