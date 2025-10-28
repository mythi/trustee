use chrono::{DateTime, Utc};
use serde::Deserialize;
use strum_macros::{Display, EnumString};

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct TcbInfo {
    tcb_info: TcbInfoData,
    signature: String,
}

// TcbInfo struct is used to map response from tcbInfo field
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct TcbInfoData {
    id: String,
    version: u8,
    issue_date: DateTime<Utc>,
    next_update: DateTime<Utc>,
    #[serde(with = "hex")]
    fmspc: Vec<u8>,
    #[serde(with = "hex")]
    pce_id: Vec<u8>,
    tcb_type: u8,
    tcb_evaluation_data_number: u32,
    #[serde(default)]
    tdx_module: TdxModule,
    #[serde(default)]
    tdx_module_identities: Vec<TdxModuleIdentity>,
    tcb_levels: Vec<TcbLevel>,
}

// TdxModule struct is used to map response from tcbInfo for tdxModule field
#[allow(dead_code)]
#[derive(Deserialize, Default)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct TdxModule {
    #[serde(with = "hex")]
    mrsigner: Vec<u8>,
    #[serde(with = "hex")]
    attributes: Vec<u8>,
    #[serde(with = "hex")]
    attributes_mask: Vec<u8>,
}

// TdxModuleIdentity struct is used to map response from tcbInfo for TdxModuleIdentity field
#[allow(dead_code)]
#[derive(Deserialize, Default)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct TdxModuleIdentity {
    id: String,
    #[serde(with = "hex")]
    mrsigner: Vec<u8>,
    #[serde(with = "hex")]
    attributes: Vec<u8>,
    #[serde(with = "hex")]
    attributes_mask: Vec<u8>,
    tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Deserialize, EnumString, Display)]
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
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct TcbLevel {
    tcb: Tcb,
    tcb_date: DateTime<Utc>,
    tcb_status: TcbStatus,
    #[serde(default)]
    advisory_ids: Vec<String>,
}

// Tcb struct is used to map TCB field
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct Tcb {
    #[serde(default)]
    sgxtcbcomponents: Vec<TcbComponent>,
    #[serde(default)]
    pcesvn: u16,
    #[serde(default)]
    tdxtcbcomponents: Vec<TcbComponent>,
    #[serde(default)]
    isvsvn: u32,
}

// TcbComponent struct is used to map sgx/tdx tcb components
#[allow(dead_code)]
#[derive(Deserialize, Default)]
pub struct TcbComponent {
    svn: u8,
    #[serde(default)]
    category: String,
    #[serde(default)]
    r#type: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct QeIdentity {
    enclave_identity: EnclaveIdentity,
    signature: String,
}

// TcbInfo struct is used to map response from tcbInfo field
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct EnclaveIdentity {
    id: String,
    version: u8,
    issue_date: DateTime<Utc>,
    next_update: DateTime<Utc>,
    tcb_evaluation_data_number: u32,
    #[serde(with = "hex")]
    miscselect: Vec<u8>,
    #[serde(with = "hex")]
    miscselect_mask: Vec<u8>,
    #[serde(with = "hex")]
    attributes: Vec<u8>,
    #[serde(with = "hex")]
    attributes_mask: Vec<u8>,
    #[serde(with = "hex")]
    mrsigner: Vec<u8>,
    #[serde(default)]
    isv_prod_id: u16,
    tcb_levels: Vec<TcbLevel>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_tcb_info() {
        // TODO: add SGX FMSCP TcbInfo
        let tcb_info_data =
            std::fs::read_to_string("./test_data/tcbInfo.json").expect("tcbInfo read");
        let _d: TcbInfo = serde_json::from_str(&tcb_info_data).expect("tcbInfo Deserialize");
    }

    #[test]
    fn deserialize_enclave_identity() {
        // TODO: add SGX QE Identity
        let enclave_identity_data = std::fs::read_to_string("./test_data/enclaveIdentity.json")
            .expect("enclaveIdentity read");
        let _d: QeIdentity =
            serde_json::from_str(&enclave_identity_data).expect("QeIdentity Deserialize");
    }
}
