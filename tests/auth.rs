#![allow(clippy::unwrap_used)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use dyndns_rfc2136::auth::{AuthDb, RequestError, ensure_host_authorized, parse_and_authenticate};
use dyndns_rfc2136::config::{Credential, Host};
use hyper::Uri;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn auth() -> AuthDb {
    AuthDb::new(&[Credential {
        username: "router".into(),
        password: "s3cret".into(),
    }])
}

#[test]
fn accepts_basic_auth_and_ipv4() {
    let uri: Uri = "/nic/update?hostname=Home.Example.org.&myip=192.0.2.4"
        .parse()
        .unwrap();
    let header = format!("Basic {}", STANDARD.encode("router:s3cret"));
    let update = parse_and_authenticate(&uri, Some(&header), &auth()).unwrap();
    assert_eq!(update.hostname, "home.example.org");
    assert_eq!(update.address, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)));
}

#[test]
fn basic_scheme_is_case_insensitive() {
    let uri: Uri = "/nic/update?hostname=home.example.org&myip=192.0.2.4"
        .parse()
        .unwrap();
    let header = format!("basic {}", STANDARD.encode("router:s3cret"));
    assert!(parse_and_authenticate(&uri, Some(&header), &auth()).is_ok());
}

#[test]
fn accepts_query_credentials_and_ipv6() {
    let uri: Uri = "/nic/update?hostname=home.example.org&myip=2001%3Adb8%3A%3A5&username=router&password=s3cret"
        .parse().unwrap();
    let update = parse_and_authenticate(&uri, None, &auth()).unwrap();
    assert_eq!(
        update.address,
        IpAddr::V6("2001:db8::5".parse::<Ipv6Addr>().unwrap())
    );
}

#[test]
fn rejects_bad_or_conflicting_credentials() {
    let uri: Uri =
        "/nic/update?hostname=home.example.org&myip=192.0.2.4&username=router&password=s3cret"
            .parse()
            .unwrap();
    let wrong = format!("Basic {}", STANDARD.encode("router:wrong"));
    assert_eq!(
        parse_and_authenticate(&uri, Some(&wrong), &auth()),
        Err(RequestError::Authentication)
    );
}

#[test]
fn rejects_unknown_duplicate_and_invalid_fields() {
    for query in [
        "/nic/update?hostname=home.example.org&hostname=other.example.org&myip=192.0.2.4&username=router&password=s3cret",
        "/nic/update?hostname=home.example.org&myip=not-an-ip&username=router&password=s3cret",
        "/nic/update?hostname=home.example.org&myip=192.0.2.4&username=router&password=s3cret&type=TXT",
        "/other?hostname=home.example.org&myip=192.0.2.4&username=router&password=s3cret",
    ] {
        let uri: Uri = query.parse().unwrap();
        assert_eq!(
            parse_and_authenticate(&uri, None, &auth()),
            Err(RequestError::Invalid)
        );
    }
}

#[test]
fn enforces_owner_username_and_address_family() {
    let host = Host {
        hostname: "home.example.org".into(),
        zone: "example.org".into(),
        username: "router".into(),
        allow_ipv4: true,
        allow_ipv6: false,
    };
    let hosts = HashMap::from([("home.example.org".into(), host)]);
    let uri: Uri = "/nic/update?hostname=home.example.org&myip=2001%3Adb8%3A%3A5&username=router&password=s3cret"
        .parse().unwrap();
    let update = parse_and_authenticate(&uri, None, &auth()).unwrap();
    assert!(ensure_host_authorized(&update, &hosts).is_err());
}
