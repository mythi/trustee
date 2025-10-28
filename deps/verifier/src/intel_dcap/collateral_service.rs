use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoJson {
    tcb_info: TcbInfo,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

// TcbInfo struct is used to map response from tcbInfo field
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    id: String,
    version: u8,
    issue_date: DateTime<Utc>,
    next_update: DateTime<Utc>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    fmspc: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    pce_id: Vec<u8>,
    tcb_type: u8,
    tcb_evaluation_data_number: u32,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    tdx_module: Option<TdxModule>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    tdx_module_identities: Option<Vec<TdxModuleIdentity>>,
    tcb_levels: Vec<TcbLevel>,
}

// TdxModule struct is used to map response from tcbInfo for tdxModule field
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    mrsigner: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    attributes: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    attributes_mask: Vec<u8>,
}

// TdxModuleIdentity struct is used to map response from tcbInfo for TdxModuleIdentity field
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    id: String,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    mrsigner: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    attributes: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    attributes_mask: Vec<u8>,
    tcb_levels: Vec<TcbLevel>,
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
    tcb: Tcb,
    tcb_date: DateTime<Utc>,
    tcb_status: TcbStatus,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    advisoryIDs: Option<Vec<String>>,
}

// Tcb struct is used to map TCB field
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tcb {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    sgxtcbcomponents: Option<Vec<TcbComponent>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pcesvn: Option<u16>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    tdxtcbcomponents: Option<Vec<TcbComponent>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    isvsvn: Option<u32>,
}

// TcbComponent struct is used to map sgx/tdx tcb components
#[derive(Serialize, Deserialize, Default)]
pub struct TcbComponent {
    svn: u8,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity {
    enclave_identity: EnclaveIdentity,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

// TcbInfo struct is used to map response from tcbInfo field
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    id: String,
    version: u8,
    issue_date: DateTime<Utc>,
    next_update: DateTime<Utc>,
    tcb_evaluation_data_number: u32,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    miscselect: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    miscselect_mask: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    attributes: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    attributes_mask: Vec<u8>,
    #[serde(serialize_with = "hex::serialize_upper")]
    #[serde(deserialize_with = "hex::deserialize")]
    mrsigner: Vec<u8>,
    isvprodid: u16,
    tcb_levels: Vec<TcbLevel>,
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
