use crate::config::{ConfigError, Credential, canonical_name};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hyper::Uri;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use subtle::ConstantTimeEq;
use thiserror::Error;

const MAX_QUERY_BYTES: usize = 1024;
const MAX_AUTH_BYTES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateRequest {
    pub hostname: String,
    pub address: IpAddr,
    pub username: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestError {
    #[error("request path or query is invalid")]
    Invalid,
    #[error("authentication is missing or invalid")]
    Authentication,
}

pub struct AuthDb {
    passwords: HashMap<String, [u8; 32]>,
}

impl AuthDb {
    #[must_use]
    pub fn new(credentials: &[Credential]) -> Self {
        Self {
            passwords: credentials
                .iter()
                .map(|credential| (credential.username.clone(), digest(&credential.password)))
                .collect(),
        }
    }

    #[must_use]
    pub fn verify(&self, username: &str, password: &str) -> bool {
        let candidate = digest(password);
        self.passwords
            .get(username)
            .is_some_and(|expected| bool::from(expected.ct_eq(&candidate)))
    }
}

pub fn parse_and_authenticate(
    uri: &Uri,
    authorization: Option<&str>,
    auth: &AuthDb,
) -> Result<UpdateRequest, RequestError> {
    if uri.path() != "/nic/update" {
        return Err(RequestError::Invalid);
    }
    let query = uri.query().ok_or(RequestError::Invalid)?;
    if query.len() > MAX_QUERY_BYTES {
        return Err(RequestError::Invalid);
    }

    let mut fields: HashMap<String, String> = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if !matches!(key.as_ref(), "hostname" | "myip" | "username" | "password")
            || fields
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(RequestError::Invalid);
        }
    }
    let hostname = canonical_name(fields.get("hostname").ok_or(RequestError::Invalid)?)
        .map_err(|_| RequestError::Invalid)?;
    let address = fields
        .get("myip")
        .ok_or(RequestError::Invalid)?
        .parse()
        .map_err(|_| RequestError::Invalid)?;
    let query_auth = match (fields.get("username"), fields.get("password")) {
        (Some(username), Some(password)) => Some((username.as_str(), password.as_str())),
        (None, None) => None,
        _ => return Err(RequestError::Authentication),
    };
    let basic_auth = authorization.map(parse_basic).transpose()?;
    let (username, password) = match (basic_auth.as_ref(), query_auth) {
        (Some((basic_user, basic_pass)), Some((query_user, query_pass))) => {
            if basic_user != query_user || !secret_eq(basic_pass, query_pass) {
                return Err(RequestError::Authentication);
            }
            (basic_user.as_str(), basic_pass.as_str())
        }
        (Some((username, password)), None) => (username.as_str(), password.as_str()),
        (None, Some(pair)) => pair,
        (None, None) => return Err(RequestError::Authentication),
    };
    if !auth.verify(username, password) {
        return Err(RequestError::Authentication);
    }
    Ok(UpdateRequest {
        hostname,
        address,
        username: username.to_owned(),
    })
}

fn parse_basic(value: &str) -> Result<(String, String), RequestError> {
    if value.len() > MAX_AUTH_BYTES {
        return Err(RequestError::Authentication);
    }
    let (scheme, encoded) = value.split_once(' ').ok_or(RequestError::Authentication)?;
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
        return Err(RequestError::Authentication);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| RequestError::Authentication)?;
    let decoded = String::from_utf8(decoded).map_err(|_| RequestError::Authentication)?;
    let (username, password) = decoded
        .split_once(':')
        .ok_or(RequestError::Authentication)?;
    if username.is_empty() || password.is_empty() {
        return Err(RequestError::Authentication);
    }
    Ok((username.to_owned(), password.to_owned()))
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn secret_eq(left: &str, right: &str) -> bool {
    bool::from(digest(left).ct_eq(&digest(right)))
}

pub fn ensure_host_authorized<S: std::hash::BuildHasher>(
    request: &UpdateRequest,
    hosts: &HashMap<String, crate::config::Host, S>,
) -> Result<crate::config::Host, ConfigError> {
    let host = hosts
        .get(&request.hostname)
        .ok_or_else(|| ConfigError::Invalid("hostname is not configured".into()))?;
    if host.username != request.username {
        return Err(ConfigError::Invalid(
            "credential cannot update this hostname".into(),
        ));
    }
    match request.address {
        IpAddr::V4(_) if !host.allow_ipv4 => {
            Err(ConfigError::Invalid("IPv4 is not allowed".into()))
        }
        IpAddr::V6(_) if !host.allow_ipv6 => {
            Err(ConfigError::Invalid("IPv6 is not allowed".into()))
        }
        _ => Ok(host.clone()),
    }
}
