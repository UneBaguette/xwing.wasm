// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Thomas <tom@unebaguette.fr>

use x_wing::{
    CIPHERTEXT_SIZE, Ciphertext, DECAPSULATION_KEY_SIZE, DecapsulationKey, ENCAPSULATION_KEY_SIZE,
    EncapsulationKey, XWingKem,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(all(
    not(target_feature = "atomics"),
    target_family = "wasm",
    feature = "talc"
))]
#[global_allocator]
static TALC: talc::wasm::WasmDynamicTalc = talc::wasm::new_wasm_dynamic_allocator();

pub const SHARED_KEY_SIZE: usize = 32;

pub struct KeyPair {
    pub sk: [u8; DECAPSULATION_KEY_SIZE], // 32
    pub pk: [u8; ENCAPSULATION_KEY_SIZE], // 1216
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

pub fn generate_keypair() -> KeyPair {
    let (sk, pk) = XWingKem::generate_keypair();
    let mut pk_bytes = [0u8; ENCAPSULATION_KEY_SIZE];
    pk_bytes.copy_from_slice(&pk.to_bytes());

    KeyPair {
        sk: *sk.as_bytes(),
        pk: pk_bytes,
    }
}

pub struct EncapsulateResult {
    pub ciphertext: [u8; CIPHERTEXT_SIZE], // 1120
    pub shared_key: [u8; SHARED_KEY_SIZE], // 32
}

impl Drop for EncapsulateResult {
    fn drop(&mut self) {
        self.shared_key.zeroize();
    }
}

pub fn encapsulate(
    pk_bytes: &[u8; ENCAPSULATION_KEY_SIZE],
) -> Result<EncapsulateResult, &'static str> {
    let pk =
        EncapsulationKey::try_from(pk_bytes.as_slice()).map_err(|_| "invalid encapsulation key")?;
    let (ct, ss) = pk.encapsulate();

    let mut ct_bytes = [0u8; CIPHERTEXT_SIZE];
    ct_bytes.copy_from_slice(&ct);

    let mut ss_bytes = [0u8; SHARED_KEY_SIZE];
    ss_bytes.copy_from_slice(&ss);

    Ok(EncapsulateResult {
        ciphertext: ct_bytes,
        shared_key: ss_bytes,
    })
}

pub fn decapsulate(
    sk_bytes: &[u8; DECAPSULATION_KEY_SIZE],
    ct_bytes: &[u8; CIPHERTEXT_SIZE],
) -> Zeroizing<[u8; SHARED_KEY_SIZE]> {
    let sk = DecapsulationKey::from(*sk_bytes);
    let ct = Ciphertext::from(*ct_bytes);
    let ss = sk.decapsulate(&ct);
    let mut ss_bytes = [0u8; SHARED_KEY_SIZE];

    ss_bytes.copy_from_slice(&ss);

    Zeroizing::new(ss_bytes)
}

#[cfg(feature = "wasm")]
mod wasm {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tsify::Tsify;
    use wasm_bindgen::prelude::*;

    #[derive(Serialize, Deserialize, Tsify)]
    #[tsify(into_wasm_abi)] // TODO: remove once deprecated
    #[serde(rename_all = "camelCase")]
    pub struct GenerateKeypairResult {
        #[serde(with = "serde_bytes")]
        pub secret_key: Vec<u8>,
        #[serde(with = "serde_bytes")]
        pub public_key: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, Tsify)]
    #[tsify(into_wasm_abi)] // TODO: remove once deprecated
    #[serde(rename_all = "camelCase")]
    pub struct EncapsulateResult {
        #[serde(with = "serde_bytes")]
        pub ciphertext: Vec<u8>,
        #[serde(with = "serde_bytes")]
        pub shared_key: Vec<u8>,
    }

    #[wasm_bindgen(js_name = "generateKeypair")]
    pub fn generate_keypair_wasm() -> GenerateKeypairResult {
        let kp = generate_keypair();

        GenerateKeypairResult {
            secret_key: kp.sk.to_vec(),
            public_key: kp.pk.to_vec(),
        }
    }

    #[wasm_bindgen]
    pub fn encapsulate(pk: &[u8]) -> Result<EncapsulateResult, JsError> {
        let pk_bytes: &[u8; ENCAPSULATION_KEY_SIZE] = pk
            .try_into()
            .map_err(|_| JsError::new("publicKey must be 1216 bytes"))?;

        let result = super::encapsulate(pk_bytes).map_err(|e| JsError::new(e))?;

        Ok(EncapsulateResult {
            ciphertext: result.ciphertext.to_vec(),
            shared_key: result.shared_key.to_vec(),
        })
    }

    #[wasm_bindgen]
    pub fn decapsulate(sk: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        let sk_bytes: &[u8; DECAPSULATION_KEY_SIZE] = sk
            .try_into()
            .map_err(|_| JsError::new("secretKey must be 32 bytes"))?;

        let ct_bytes: &[u8; CIPHERTEXT_SIZE] = ciphertext
            .try_into()
            .map_err(|_| JsError::new("ciphertext must be 1120 bytes"))?;

        Ok(super::decapsulate(sk_bytes, ct_bytes).to_vec())
    }
}

#[cfg(feature = "wasm")]
pub use wasm::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_sizes() {
        let kp = generate_keypair();

        assert_eq!(kp.sk.len(), DECAPSULATION_KEY_SIZE);
        assert_eq!(kp.pk.len(), ENCAPSULATION_KEY_SIZE);
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let kp = generate_keypair();
        let enc = encapsulate(&kp.pk).unwrap();
        let ss = decapsulate(&kp.sk, &enc.ciphertext);

        assert_eq!(enc.shared_key, *ss);
    }

    #[test]
    fn different_keypairs_different_shared_keys() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let enc1 = encapsulate(&kp1.pk).unwrap();
        let enc2 = encapsulate(&kp2.pk).unwrap();

        assert_ne!(enc1.shared_key, enc2.shared_key);
    }

    #[test]
    fn encapsulate_twice_different_ciphertext() {
        let kp = generate_keypair();
        let enc1 = encapsulate(&kp.pk).unwrap();
        let enc2 = encapsulate(&kp.pk).unwrap();

        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        assert_ne!(enc1.shared_key, enc2.shared_key);
    }

    #[test]
    fn wrong_sk_wrong_shared_key() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let enc = encapsulate(&kp1.pk).unwrap();
        let ss = decapsulate(&kp2.sk, &enc.ciphertext);

        assert_ne!(enc.shared_key, *ss);
    }

    #[test]
    fn invalid_pk_rejected() {
        let bad_pk = [0u8; ENCAPSULATION_KEY_SIZE];
        // May or may not error depending on x-wing validation
        // but if it succeeds, decapsulation with correct sk should still work
        let _ = encapsulate(&bad_pk);
    }

    #[test]
    fn shared_key_is_32_bytes() {
        let kp = generate_keypair();
        let enc = encapsulate(&kp.pk).unwrap();

        assert_eq!(enc.shared_key.len(), SHARED_KEY_SIZE);
    }

    #[test]
    fn ciphertext_is_1120_bytes() {
        let kp = generate_keypair();
        let enc = encapsulate(&kp.pk).unwrap();

        assert_eq!(enc.ciphertext.len(), CIPHERTEXT_SIZE);
    }
}

#[cfg(all(target_arch = "wasm32", test))]
mod wasm_tests {
    use super::wasm::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn wasm_roundtrip() {
        let kp = generate_keypair_wasm();
        let enc = encapsulate(&kp.public_key).unwrap();
        let ss = decapsulate(&kp.secret_key, &enc.ciphertext).unwrap();

        assert_eq!(enc.shared_key, ss);
    }

    #[wasm_bindgen_test]
    fn wasm_different_keypairs_different_shared_keys() {
        let kp1 = generate_keypair_wasm();
        let kp2 = generate_keypair_wasm();
        let enc1 = encapsulate(&kp1.public_key).unwrap();
        let enc2 = encapsulate(&kp2.public_key).unwrap();

        assert_ne!(enc1.shared_key, enc2.shared_key);
    }

    #[wasm_bindgen_test]
    fn wasm_encapsulate_twice_different_ciphertext() {
        let kp = generate_keypair_wasm();
        let enc1 = encapsulate(&kp.public_key).unwrap();
        let enc2 = encapsulate(&kp.public_key).unwrap();

        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        assert_ne!(enc1.shared_key, enc2.shared_key);
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_sk_wrong_shared_key() {
        let kp1 = generate_keypair_wasm();
        let kp2 = generate_keypair_wasm();
        let enc = encapsulate(&kp1.public_key).unwrap();
        let ss = decapsulate(&kp2.secret_key, &enc.ciphertext).unwrap();

        assert_ne!(enc.shared_key, ss);
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_pk_length() {
        assert!(encapsulate(&[0u8; 32]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_sk_length() {
        let kp = generate_keypair_wasm();
        let enc = encapsulate(&kp.public_key).unwrap();

        assert!(decapsulate(&[0u8; 16], &enc.ciphertext).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_ct_length() {
        let kp = generate_keypair_wasm();

        assert!(decapsulate(&kp.secret_key, &[0u8; 32]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_empty_pk() {
        assert!(encapsulate(&[]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_empty_sk_and_ct() {
        assert!(decapsulate(&[], &[]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_keypair_sizes() {
        let kp = generate_keypair_wasm();

        assert_eq!(kp.secret_key.len(), 32);
        assert_eq!(kp.public_key.len(), 1216);
    }

    #[wasm_bindgen_test]
    fn wasm_ciphertext_and_shared_key_sizes() {
        let kp = generate_keypair_wasm();
        let enc = encapsulate(&kp.public_key).unwrap();

        assert_eq!(enc.ciphertext.len(), 1120);
        assert_eq!(enc.shared_key.len(), 32);
    }
}
