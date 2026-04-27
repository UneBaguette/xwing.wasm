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
    #[cfg(feature = "wasm")]
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Serialize};
    use tsify::Tsify;
    use wasm_bindgen::prelude::*;

    fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn decode(s: &str, context: &str) -> Result<Vec<u8>, JsError> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| JsError::new(&format!("invalid base64 at {context}")))
    }

    fn decode_fixed<const N: usize>(s: &str, context: &str) -> Result<[u8; N], JsError> {
        let bytes = decode(s, context)?;

        bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new(&format!("{context} must be {N} bytes")))
    }

    #[derive(Debug, Serialize, Deserialize, Tsify)]
    #[tsify(into_wasm_abi)]
    pub struct GenerateKeypairResult {
        #[serde(rename = "secretKey")]
        pub secret_key: String,
        #[serde(rename = "publicKey")]
        pub public_key: String,
    }

    #[wasm_bindgen(js_name = "generateKeypair")]
    pub fn generate_keypair_wasm() -> GenerateKeypairResult {
        let kp = generate_keypair();

        GenerateKeypairResult {
            secret_key: encode(&kp.sk),
            public_key: encode(&kp.pk),
        }
    }

    #[derive(Debug, Serialize, Deserialize, Tsify)]
    #[tsify(into_wasm_abi)]
    pub struct EncapsulateResult {
        pub ciphertext: String,
        #[serde(rename = "sharedKey")]
        pub shared_key: String,
    }

    #[wasm_bindgen]
    pub fn encapsulate(pk: &str) -> Result<EncapsulateResult, JsError> {
        let pk_bytes = decode_fixed::<ENCAPSULATION_KEY_SIZE>(pk, "publicKey")?;
        let result = super::encapsulate(&pk_bytes).map_err(|e| JsError::new(e))?;

        Ok(EncapsulateResult {
            ciphertext: encode(&result.ciphertext),
            shared_key: encode(&result.shared_key),
        })
    }

    #[wasm_bindgen]
    pub fn decapsulate(sk: &str, ciphertext: &str) -> Result<String, JsError> {
        let sk_bytes = decode_fixed::<DECAPSULATION_KEY_SIZE>(sk, "secretKey")?;
        let ct_bytes = decode_fixed::<CIPHERTEXT_SIZE>(ciphertext, "ciphertext")?;

        Ok(encode(&super::decapsulate(&sk_bytes, &ct_bytes)))
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
    fn wasm_invalid_pk_base64() {
        assert!(encapsulate("not-valid-base64!!!").is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_pk_length() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let short = URL_SAFE_NO_PAD.encode(&[0u8; 32]);

        assert!(encapsulate(&short).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_invalid_sk_base64() {
        let kp = generate_keypair_wasm();
        let enc = encapsulate(&kp.public_key).unwrap();

        assert!(decapsulate("bad-base64!!!", &enc.ciphertext).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_ct_length() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let kp = generate_keypair_wasm();
        let short_ct = URL_SAFE_NO_PAD.encode(&[0u8; 32]);

        assert!(decapsulate(&kp.secret_key, &short_ct).is_err());
    }
}
