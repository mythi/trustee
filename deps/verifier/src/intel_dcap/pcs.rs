use super::collateral_service::{
    CollateralData, CollateralService, CollateralType, IntelTee,
};
use http_cache_reqwest::{
    Cache, CacheMode, HttpCache, HttpCacheOptions, MokaCacheBuilder, MokaManager,
};
use reqwest_middleware::ClientBuilder;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info};
use urlencoding::decode;

/// 7-day max-age applied to all PCS responses regardless of what the server advertises.
const PCS_CACHE_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

static PCS_CACHE_MANAGER: OnceLock<MokaManager> = OnceLock::new();

fn init_cache_manager() -> MokaManager {
    MokaManager::new(MokaCacheBuilder::new(1024).build())
}

pub struct Pcs {
    client: reqwest_middleware::ClientWithMiddleware,
    url: reqwest::Url,
    api_version: u8,
}

// TODO: define proper errors
#[derive(Error, Debug)]
pub enum PcsError {
    #[error("Request error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Request error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Header decoding error: {0}")]
    HeaderDecoding(#[from] std::string::FromUtf8Error),
}

impl Pcs {
    /// Returns the HTTP response header name that carries the certificate chain for the
    /// given collateral type, or `None` when the PCS response carries no such header.
    fn cert_chain_header(ct: &CollateralType<'_>) -> Option<&'static str> {
        match ct {
            CollateralType::TcbInfo(..) => Some("tcb-info-issuer-chain"),
            CollateralType::QeIdentity(..) => Some("sgx-enclave-identity-issuer-chain"),
            CollateralType::PckCrl(..) => Some("sgx-pck-crl-issuer-chain"),
            CollateralType::RootCaCrl(_) => None,
        }
    }

    pub fn new(url: reqwest::Url, api_version: u8) -> Self {
        let manager = PCS_CACHE_MANAGER.get_or_init(init_cache_manager).clone();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(Cache(HttpCache {
                mode: CacheMode::ForceCache,
                manager,
                options: HttpCacheOptions {
                    cache_status_headers: true,
                    max_ttl: Some(PCS_CACHE_MAX_AGE),
                    ..Default::default()
                },
            }))
            .build();
        Self {
            client,
            url,
            api_version,
        }
    }
}

impl CollateralService for Pcs {
    type Error = PcsError;

    async fn get(
        &self,
        ct: CollateralType<'_>,
    ) -> Result<CollateralData, PcsError> {
        let mut params = HashMap::new();

        let url = match ct {
            CollateralType::TcbInfo(tee, fmspc) => {
                // TODO: CollateralService implementions can add service specific query params, e.g., "update"
                // params.insert("update", "early");
                params.insert("fmspc", fmspc);
                self.url
                    .join(format!("{tee}/certification/v{}/tcb", self.api_version).as_str())
                    .map_err(PcsError::UrlParse)?
            }
            CollateralType::QeIdentity(tee) => self
                .url
                .join(format!("{tee}/certification/v{}/qe/identity", self.api_version).as_str())
                .map_err(PcsError::UrlParse)?,
            CollateralType::PckCrl(ca, encoding) => {
                params.insert("ca", ca);
                params.insert("encoding", encoding);
                self.url
                    .join(format!("sgx/certification/v{}/pckcrl", self.api_version).as_str())
                    .map_err(PcsError::UrlParse)?
            }
            CollateralType::RootCaCrl(crl_distpoint) => crl_distpoint.map_or_else(
                || {
                    self.url
                        .join(format!("sgx/certification/v{}/rootcacrl", self.api_version).as_str())
                        .map_err(PcsError::UrlParse)
                },
                |crl| reqwest::Url::parse(crl).map_err(PcsError::UrlParse),
            )?,
        };

        // Append query params to the URL; reqwest_middleware::RequestBuilder does not
        // expose .query(), so we build the query string directly on the URL.
        let mut url = url;
        url.query_pairs_mut().extend_pairs(params.iter());

        // TODO: better error response handling
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(PcsError::ReqwestMiddleware)?;

        if let Some(cache_status) = response.headers().get("x-cache") {
            let status = cache_status.to_str().unwrap_or("?");
            debug!(url = %url, status, "PCS cache status");
            if status.eq_ignore_ascii_case("HIT") {
                info!(url = %url, "PCS cache hit");
            }
        }
        let chain = if let Some(header) = Pcs::cert_chain_header(&ct) {
            if let Some(certchain) = response.headers().get(header) {
                let c = certchain.to_str().unwrap_or_default();
                let decoded_chain = decode(c).map_err(PcsError::HeaderDecoding)?;
                Some(Vec::from(decoded_chain.as_bytes()))
            } else {
                None
            }
        } else {
            None
        };

        let body = Vec::from(response.bytes().await?);
        Ok(CollateralData { body, cert_chain: chain })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel_dcap::collateral_service::{IntelTee, TcbInfoJson};

    #[tokio::test]
    async fn tcb_info_signature() {
        use openssl::bn::BigNum;
        use openssl::ec::EcKey;
        use openssl::ecdsa::EcdsaSig;
        use openssl::sha::sha256;
        use openssl::x509::X509;
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let url = reqwest::Url::parse("https://api.trustedservices.intel.com/").expect("parse");
        let pcs = Pcs::new(url, 4);
        let CollateralData { body: tcb, cert_chain: chain } = pcs
            .get(CollateralType::TcbInfo(&IntelTee::Tdx, "90c06f000000"))
            .await
            .expect("Get TcbInfo Collateral from PCS");

        assert!(!tcb.is_empty());
        assert!(chain.is_some());

        let chain = X509::stack_from_pem(chain.unwrap().as_slice())
            .expect("Parse TcbInfo signing certificates");

        assert!(chain.len() == 2);

        let d: TcbInfoJson =
            serde_json::from_slice(tcb.as_slice()).expect("Deserialize TcbInfoJson");

        assert!(d.signature.len() == 64);

        let public_key = chain[0]
            .public_key()
            .expect("Get public key from the signing certificate");

        let r = BigNum::from_slice(&d.signature[..32]).expect("Signature R Bignum");
        let s = BigNum::from_slice(&d.signature[32..]).expect("Signature S Bignum");
        let ecdsa_sig = EcdsaSig::from_private_components(r, s).expect("ECDSA Signature");

        // Serialize TCBInfo back to JSON for signature checking.
        let bytes = serde_json::to_vec(&d.tcb_info).expect("Serialize to bytes");

        let ec_key = EcKey::try_from(public_key).expect("Take EC key from OpenSSL pkey");

        assert!(ecdsa_sig
            .verify(&sha256(bytes.as_slice()), &ec_key)
            .is_ok_and(|res| res));
    }
}
