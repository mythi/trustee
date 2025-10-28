use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::{Display, EnumString};

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
    #[serde(
        serialize_with = "hex::serialize_upper",
        deserialize_with = "hex::deserialize"
    )]
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

// ---------------------------------------------------------------------------
// platform_collaterals.json deserialization
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
pub struct PlatformCollaterals {
    pub collaterals: PcsCollaterals,
}

impl PlatformCollaterals {
    pub fn from_json_str(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn from_reader<R: std::io::Read>(r: R) -> Result<Self, serde_json::Error> {
        serde_json::from_reader(r)
    }
}

#[derive(Deserialize, Serialize)]
pub struct PcsCollaterals {
    pub version: u32,
    pub tcbinfos: Vec<TcbInfoEntry>,
    pub pckcacrl: PckCaCrl,

    /// QE enclave identity (raw JSON string).
    pub qeidentity: String,
    #[serde(default)]
    pub qeidentity_early: Option<String>,

    /// TD QE enclave identity (raw JSON string).
    pub tdqeidentity: String,
    #[serde(default)]
    pub tdqeidentity_early: Option<String>,

    pub certificates: PcsCollateralCertificates,

    /// Root CA CRL (hex-encoded DER).
    pub rootcacrl: String,
    #[serde(default)]
    pub rootcacrl_cdp: Option<String>,
}

/// One FMSPC entry in `collaterals.tcbinfos`.
///
/// TDX TCB info is optional and only present when the FMSPC corresponds to a TDX-capable platform.
/// The `_early` variants are present only when the tool was run with `tcb_update_type = all`.
#[derive(Deserialize, Serialize)]
pub struct TcbInfoEntry {
    #[serde(with = "hex")]
    pub fmspc: [u8; 6],

    #[serde(default)]
    pub sgx_tcbinfo: Option<TcbInfoJson>,
    #[serde(default)]
    pub sgx_tcbinfo_early: Option<TcbInfoJson>,

    #[serde(default)]
    pub tdx_tcbinfo: Option<TcbInfoJson>,
    #[serde(default)]
    pub tdx_tcbinfo_early: Option<TcbInfoJson>,
}

#[derive(Deserialize, Serialize)]
pub struct PckCaCrl {
    #[serde(rename = "processorCrl")]
    pub processor_crl: String,
    #[serde(rename = "platformCrl", default)]
    pub platform_crl: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct PcsCollateralCertificates {
    #[serde(rename = "TCB-Info-Issuer-Chain")]
    pub tcb_info_issuer_chain: String,
    #[serde(rename = "SGX-Enclave-Identity-Issuer-Chain")]
    pub enclave_identity_issuer_chain: String,
    /// PEM chain for the intermediate CA that issues PCK CRLs and PCK certificates,
    /// keyed by CA type ("PLATFORM", "PROCESSOR").
    #[serde(rename = "SGX-PCK-Certificate-Issuer-Chain", default)]
    pub pck_crl_issuer_chain: HashMap<String, String>,
}

/// The collateral fetched from a `CollateralService`: the response body and an optional
/// PEM-encoded certificate chain extracted from the response headers.
pub struct CollateralData {
    pub body: Vec<u8>,
    pub cert_chain: Option<Vec<u8>>,
}

pub enum CollateralType<'a> {
    TcbInfo(&'a IntelTee, &'a str),
    QeIdentity(&'a IntelTee),
    PckCrl(&'a str, &'a str),
    RootCaCrl(Option<&'a str>),
}

#[derive(Display)]
#[strum(serialize_all = "lowercase")]
pub enum IntelTee {
    Sgx,
    Tdx,
}

pub trait CollateralService: Send + Sync {
    type Error: std::error::Error;

    async fn get(&self, ct: CollateralType<'_>) -> Result<CollateralData, Self::Error>;
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
}
