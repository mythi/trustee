use kbs_protocol::{
    evidence_provider::NativeEvidenceProvider, KbsClientBuilder, KbsClientCapabilities,
};
use std::env;
use std::fs::{read_to_string, write};
use thiserror::Error;
use tokio::runtime;

#[derive(Error, Debug)]
enum SecretProvisionHandlerError {
    #[error("Gramine Manifest Env Configuration error: SECRET_PROVISION_{0}: {1}")]
    GramineEnvConfig(&'static str, #[source] std::env::VarError),

    #[error("Gramine IO error: {0}")]
    GramineIO(#[from] std::io::Error),

    #[error("Gramine Get Resource error: {0}")]
    GramineGetResource(#[from] kbs_protocol::Error),

    #[error("Gramine Key Length error: {0}")]
    GramineKey(String),
}

fn secret_provision_handler() -> Result<(), SecretProvisionHandlerError> {
    // TODO: only one server is currently allowed
    let server = env::var("SECRET_PROVISION_SERVERS")
        .map_err(|e| SecretProvisionHandlerError::GramineEnvConfig("SERVERS", e))?;

    // TODO: not found not an error (set SECRET_PROVISION_SECRET_STRING instead)
    let key_url = env::var("SECRET_PROVISION_SET_KEY")
        .map_err(|e| SecretProvisionHandlerError::GramineEnvConfig("SET_KEY", e))?;

    let ca_path = env::var("SECRET_PROVISION_CA_CHAIN_PATH")
        .map_err(|e| SecretProvisionHandlerError::GramineEnvConfig("CA_CHAIN_PATH", e))?;

    let cert = read_to_string(ca_path).map_err(|e| SecretProvisionHandlerError::GramineIO(e))?;

    let rt = runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .unwrap();

    let evidence_provider = Box::new(NativeEvidenceProvider::new().unwrap());

    let mut client = KbsClientBuilder::with_evidence_provider(evidence_provider, server.as_str())
        .add_kbs_cert(cert.as_str())
        .build()
        .unwrap();

    let mut res: Result<Vec<u8>, kbs_protocol::Error> = Ok(vec![]);

    rt.block_on(async {
        res = client
            .get_resource(format!("kbs:///{key_url}").as_str().try_into().unwrap())
            .await
    });

    let secret = res.map_err(|e| SecretProvisionHandlerError::GramineGetResource(e))?;

    let pf_key = key_url.rsplitn(3, '/').next().unwrap();

    // Encrypted files keys' length must be 16 bytes
    if secret.len() != 16 {
        return Err(SecretProvisionHandlerError::GramineKey(format!(
            "len({pf_key})={}",
            secret.len()
        )));
    }

    write(format!("/dev/attestation/keys/{pf_key}"), secret)
        .map_err(|e| SecretProvisionHandlerError::GramineIO(e))?;

    Ok(())
}

#[no_mangle]
#[link_section = ".init_array"]
pub static ld_preload_init: extern "C" fn() = self::secret_provision_constructor;
extern "C" fn secret_provision_constructor() {
    let constructor = match env::var("SECRET_PROVISION_CONSTRUCTOR") {
        Ok(val) if val == "true" || val == "TRUE" || val == "1" => true,
        _ => false,
    };

    if constructor {
        // "immediately unset envvar so that execve'd child processes do not land here (otherwise
        // secret provisioning would happen for each new child, but each child already got all the
        // secrets from the parent process during checkpoint-and-restore)"
        env::remove_var("SECRET_PROVISION_CONSTRUCTOR");
        //env::remove_var("SECRET_PROVISION_SECRET_STRING");

        match secret_provision_handler() {
            Err(e) => println!("Error: {e}"),
            _ => println!("OK"),
        };
    }
}
