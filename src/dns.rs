use crate::config::{Host, Tsig, TsigAlgorithm};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use dns_update::providers::rfc2136::DnsAddress;
use dns_update::{DnsRecord, DnsRecordType, DnsUpdater};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("TSIG secret is not valid base64")]
    Secret(#[from] base64::DecodeError),
    #[error("could not configure RFC 2136 client: {0:?}")]
    Configuration(dns_update::Error),
    #[error("RFC 2136 update failed: {0:?}")]
    Update(dns_update::Error),
}

#[derive(Clone)]
pub struct Rfc2136Writer {
    updater: DnsUpdater,
    ttl: u32,
}

impl Rfc2136Writer {
    pub fn new(server: SocketAddr, tsig: &Tsig, ttl: u32) -> Result<Self, DnsError> {
        let secret = STANDARD.decode(&tsig.secret_base64)?;
        let algorithm = match tsig.algorithm {
            TsigAlgorithm::HmacSha256 => dns_update::TsigAlgorithm::HmacSha256,
            TsigAlgorithm::HmacSha384 => dns_update::TsigAlgorithm::HmacSha384,
            TsigAlgorithm::HmacSha512 => dns_update::TsigAlgorithm::HmacSha512,
        };
        let updater = DnsUpdater::new_rfc2136_tsig(
            DnsAddress::Udp(server),
            &tsig.key_name,
            secret,
            algorithm,
        )
        .map_err(DnsError::Configuration)?;
        Ok(Self { updater, ttl })
    }

    pub async fn update(&self, host: &Host, address: IpAddr) -> Result<(), DnsError> {
        let (record_type, record) = match address {
            IpAddr::V4(value) => (DnsRecordType::A, DnsRecord::A(value)),
            IpAddr::V6(value) => (DnsRecordType::AAAA, DnsRecord::AAAA(value)),
        };
        self.updater
            .set_rrset(
                &host.hostname,
                record_type,
                self.ttl,
                vec![record],
                &host.zone,
            )
            .await
            .map_err(DnsError::Update)
    }
}
