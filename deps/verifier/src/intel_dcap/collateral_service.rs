use chrono::{DateTime, Utc};
use http_cache_reqwest::{
    Cache, CacheMode, HttpCache, HttpCacheOptions, MokaCacheBuilder, MokaManager,
};
use reqwest_middleware::ClientBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::{Display, EnumString};
use thiserror::Error;
use urlencoding::decode;

use std::sync::OnceLock;
const NUM_TCB_COMPONENTS: usize = 16;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoJson {
    pub tcb_info: TcbInfo,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

// TcbInfo struct is used to map response from tcbInfo field
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub id: String,
    pub version: u8,
    pub issue_date: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    #[serde(with = "hex")]
    pub fmspc: [u8; 6],
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub pce_id: [u8; 2],
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_module: Option<TdxModule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_module_identities: Option<Vec<TdxModuleIdentity>>,
    pub tcb_levels: Vec<TcbLevel>,
}

// TdxModule struct is used to map response from tcbInfo for tdxModule field
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub mrsigner: Vec<u8>,
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub attributes: [u8; 8],
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub attributes_mask: [u8; 8],
}

// TdxModuleIdentity struct is used to map response from tcbInfo for TdxModuleIdentity field
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    pub id: String,
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub mrsigner: Vec<u8>,
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub attributes: [u8; 8],
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub attributes_mask: [u8; 8],
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Serialize, Deserialize, EnumString, Display)]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

// TcbLevel struct is used to map TCB Level field
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: DateTime<Utc>,
    pub tcb_status: TcbStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisoryIDs: Option<Vec<String>>,
}

// Tcb struct is used to map TCB field
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tcb {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sgxtcbcomponents: Option<TcbComponentList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcesvn: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdxtcbcomponents: Option<TcbComponentList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isvsvn: Option<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct TcbComponentList(pub [TcbComponent; NUM_TCB_COMPONENTS]);

// TcbComponent struct is used to map sgx/tdx tcb components
#[derive(Serialize, Deserialize, Default)]
pub struct TcbComponent {
    pub svn: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity {
    pub enclave_identity: EnclaveIdentity,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

// TcbInfo struct is used to map response from tcbInfo field
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    pub id: String,
    pub version: u8,
    pub issue_date: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub tcb_evaluation_data_number: u32,
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub miscselect: [u8; 4],
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub miscselect_mask: [u8; 4],
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub attributes: [u8; 16],
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub attributes_mask: [u8; 16],
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
    pub mrsigner: [u8; 32],
    pub isvprodid: u16,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Display)]
pub enum CollateralType<'a> {
    #[strum(to_string = "tcb-info-issuer-chain")]
    TcbInfo(&'a IntelTee, &'a str),
    #[strum(to_string = "sgx-enclave-identity-issuer-chain")]
    QeIdentity(&'a IntelTee),
    #[strum(to_string = "sgx-pck-crl-issuer-chain")]
    PckCrl(&'a str, &'a str),
    RootCaCrl(Option<&'a str>),
}

#[derive(Display)]
#[strum(serialize_all = "lowercase")]
pub enum IntelTee {
    Sgx,
    Tdx,
}

pub struct IntelPcs {
    pub client: reqwest_middleware::ClientWithMiddleware,
    pub url: reqwest::Url,
    pub api_version: u8,
}

// TODO: define proper errors
#[derive(Error, Debug)]
pub enum IntelPcsError {
    #[error("Request error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Request error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Header decoding error: {0}")]
    HeaderDecoding(#[from] std::string::FromUtf8Error),
}

pub trait CollateralService {
    type Error: std::error::Error;

    async fn get(&self, ct: CollateralType<'_>) -> Result<(Vec<u8>, Option<Vec<u8>>), Self::Error>;
}

impl CollateralService for IntelPcs {
    type Error = IntelPcsError;

    async fn get(
        &self,
        ct: CollateralType<'_>,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), IntelPcsError> {
        // Initialize query parameters
        let mut params = HashMap::new();

        let url = match ct {
            CollateralType::TcbInfo(tee, fmspc) => {
                // TODO: CollateralService implementions can add service specific query params, e.g., "update"
                // params.insert("update", "early");
                params.insert("fmspc", fmspc);
                self.url
                    .join(format!("{tee}/certification/v{}/tcb", self.api_version).as_str())
                    .map_err(IntelPcsError::UrlParse)?
            }
            CollateralType::QeIdentity(tee) => self
                .url
                .join(format!("{tee}/certification/v{}/qe/identity", self.api_version).as_str())
                .map_err(IntelPcsError::UrlParse)?,
            CollateralType::PckCrl(ca, encoding) => {
                params.insert("ca", ca);
                params.insert("encoding", encoding);
                self.url
                    .join(format!("sgx/certification/v{}/pckcrl", self.api_version).as_str())
                    .map_err(IntelPcsError::UrlParse)?
            }
            CollateralType::RootCaCrl(crl_distpoint) => crl_distpoint.map_or_else(
                || {
                    self.url
                        .join(format!("sgx/certification/v{}/rootcacrl", self.api_version).as_str())
                        .map_err(IntelPcsError::UrlParse)
                },
                |crl| reqwest::Url::parse(crl).map_err(IntelPcsError::UrlParse),
            )?,
        };

        // Send GET request with headers
        // TODO: better error response handling
        let response = self
            .client
            .get(url)
            .query(&params)
            .send()
            .await
            .map_err(IntelPcsError::ReqwestMiddleware)?;

        if let Some(cache_status) = response.headers().get("x-cache") {
            println!("x-cache: {:?}", cache_status);
        }
        let chain = match ct {
            CollateralType::RootCaCrl(_) => None,
            _ => {
                if let Some(certchain) = response.headers().get(ct.to_string()) {
                    let c = certchain.to_str().unwrap_or_default();
                    let decoded_chain = decode(c).map_err(IntelPcsError::HeaderDecoding)?;
                    Some(Vec::from(decoded_chain.as_bytes()))
                } else {
                    None
                }
            }
        };

        let data = Vec::from(response.bytes().await?);
        Ok((data, chain))
    }
}

static PCS_CACHE_MANAGER: OnceLock<MokaManager> = OnceLock::new();
fn init_cache_manager() -> MokaManager {
    MokaManager::new(MokaCacheBuilder::new(1024).build())
}
#[cfg(test)]
mod tests {
    use super::*;

    // TODO: 1) add signature checks with signing certs added, 2) add both SGX and TDX tcbInfo/QeIdentity
    #[test]
    fn deserialize_tcb_info() {
        let tcb_info_data =
            std::fs::read_to_string("./test_data/tcbInfo.json").expect("tcbInfo read");
        let d: TcbInfoJson = serde_json::from_str(&tcb_info_data).expect("tcbInfo Deserialize");
        // Dummy reads
        let _ = d.tcb_info;
        let _ = d.signature;
    }

    #[test]
    fn deserialize_enclave_identity() {
        let enclave_identity_data = std::fs::read_to_string("./test_data/enclaveIdentity.json")
            .expect("enclaveIdentity read");
        let d: QeIdentity =
            serde_json::from_str(&enclave_identity_data).expect("QeIdentity Deserialize");
        // Dummy reads
        let _ = d.enclave_identity;
        let _ = d.signature;
    }
    #[tokio::test]
    async fn tcb_info_signature() {
        use openssl::bn::BigNum;
        use openssl::ec::EcKey;
        use openssl::ecdsa::EcdsaSig;
        use openssl::sha::sha256;
        use openssl::x509::X509;

        let manager = PCS_CACHE_MANAGER.get_or_init(init_cache_manager).clone();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(Cache(HttpCache {
                mode: CacheMode::Default,
                manager,
                options: HttpCacheOptions {
                    cache_status_headers: true,
                    ..Default::default()
                },
            }))
            .build();

        let url = reqwest::Url::parse("https://api.trustedservices.intel.com/").expect("parse");
        let api_version = 4;
        let pcs = IntelPcs {
            client,
            url,
            api_version,
        };
        let (tcb, chain) = pcs
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
