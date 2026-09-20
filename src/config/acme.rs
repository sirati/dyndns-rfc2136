use super::ConfigError;

pub(super) fn validate_directory(value: &str) -> Result<(), ConfigError> {
    if matches!(value, "production" | "staging") {
        return Ok(());
    }
    let url = url::Url::parse(value)
        .map_err(|_| ConfigError::Invalid("invalid ACME directory URL".into()))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return invalid("ACME directory URL must use HTTP or HTTPS");
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return invalid("ACME directory URL must not contain credentials or a fragment");
    }
    if url.scheme() == "http" && !is_local_host(url.host_str().unwrap_or_default()) {
        return invalid("plain HTTP ACME directory must use a local or private address");
    }
    Ok(())
}

fn is_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| match address {
            std::net::IpAddr::V4(value) => {
                value.is_private() || value.is_loopback() || value.is_link_local()
            }
            std::net::IpAddr::V6(value) => {
                value.is_loopback() || value.is_unique_local() || value.is_unicast_link_local()
            }
        })
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(message.into()))
}
