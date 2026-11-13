use akrat_trust::{RELEASE_TRUST_ROOT_KEY_HEX, ReleaseAttestation, release_attestation_payload};
use ed25519_dalek::{Signer, SigningKey};
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let check_key = args.len() == 1 && args[0] == "--check-key";
    let paths = if check_key {
        None
    } else if args.len() == 2 {
        Some((PathBuf::from(&args[0]), PathBuf::from(&args[1])))
    } else {
        return Err("usage: akrat-sign-release-attestation [--check-key | <attestation.json> <signature.sig>]".into());
    };
    let seed = std::env::var("AKRAT_RELEASE_SIGNING_SEED")?;
    let seed: [u8; 32] = hex::decode(seed.trim())?
        .try_into()
        .map_err(|_| "release signing seed must be exactly 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let expected_key: [u8; 32] = hex::decode(RELEASE_TRUST_ROOT_KEY_HEX)?
        .try_into()
        .map_err(|_| "compiled release trust root has invalid length")?;
    if signing_key.verifying_key().to_bytes() != expected_key {
        return Err("release signing key does not match the compiled trust root".into());
    }
    if check_key {
        println!("Release signing key matches the compiled AKRAT trust root.");
        return Ok(());
    }
    let (input, output) = paths.expect("signing paths are present outside key-check mode");
    let attestation: ReleaseAttestation = serde_json::from_slice(&std::fs::read(input)?)?;
    let payload = release_attestation_payload(&attestation)?;
    let signature = signing_key.sign(&payload);
    std::fs::write(output, hex::encode(signature.to_bytes()))?;
    Ok(())
}
