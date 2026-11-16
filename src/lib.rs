// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Thomas <tom@unebaguette.fr>

use x_wing::kem::{FromSeed, Seed};
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

pub fn generate_keypair_from_seed(seed: &Seed<XWingKem>) -> KeyPair {
    let (sk, pk) = XWingKem::from_seed(seed);

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
    use tsify::{Ts, Tsify};
    use wasm_bindgen::prelude::*;

    #[derive(Serialize, Deserialize, Tsify)]
    #[serde(rename_all = "camelCase")]
    pub struct GenerateKeypairResult {
        #[tsify(type = "Uint8Array")]
        #[serde(with = "serde_bytes")]
        pub secret_key: Vec<u8>,
        #[tsify(type = "Uint8Array")]
        #[serde(with = "serde_bytes")]
        pub public_key: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, Tsify)]
    #[serde(rename_all = "camelCase")]
    pub struct EncapsulateResult {
        #[tsify(type = "Uint8Array")]
        #[serde(with = "serde_bytes")]
        pub ciphertext: Vec<u8>,
        #[tsify(type = "Uint8Array")]
        #[serde(with = "serde_bytes")]
        pub shared_key: Vec<u8>,
    }

    #[wasm_bindgen(js_name = "generateKeypair")]
    pub fn generate_keypair_wasm() -> Result<Ts<GenerateKeypairResult>, JsError> {
        let kp = generate_keypair();

        let result = GenerateKeypairResult {
            secret_key: kp.sk.to_vec(),
            public_key: kp.pk.to_vec(),
        };

        Ok(result.into_ts()?)
    }

    #[wasm_bindgen(js_name = "generateKeypairFromSeed")]
    pub fn generate_keypair_seed_wasm(seed: &[u8]) -> Result<Ts<GenerateKeypairResult>, JsError> {
        let seed = <&Seed<XWingKem>>::try_from(seed)
            .map_err(|_| JsError::new("Invalid X-Wing seed length"))?;

        let kp = generate_keypair_from_seed(seed);

        let result = GenerateKeypairResult {
            secret_key: kp.sk.to_vec(),
            public_key: kp.pk.to_vec(),
        };

        Ok(result.into_ts()?)
    }

    #[wasm_bindgen]
    pub fn encapsulate(pk: &[u8]) -> Result<Ts<EncapsulateResult>, JsError> {
        let pk_bytes: &[u8; ENCAPSULATION_KEY_SIZE] = pk
            .try_into()
            .map_err(|_| JsError::new("publicKey must be 1216 bytes"))?;

        let result = super::encapsulate(pk_bytes).map_err(|e| JsError::new(e))?;

        let out = EncapsulateResult {
            ciphertext: result.ciphertext.to_vec(),
            shared_key: result.shared_key.to_vec(),
        };

        Ok(out.into_ts()?)
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
        let bad_pk = [0xFFu8; ENCAPSULATION_KEY_SIZE];

        assert!(encapsulate(&bad_pk).is_err());
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

    #[test]
    fn seed_roundtrip() {
        let kp = generate_keypair();
        let seed = <&Seed<XWingKem>>::try_from(&kp.sk[..]).unwrap();
        let derived = generate_keypair_from_seed(seed);

        assert_eq!(derived.sk, kp.sk);
        assert_eq!(derived.pk, kp.pk);
    }

    #[test]
    fn seed_deterministic() {
        let seed = <&Seed<XWingKem>>::try_from(&[7u8; 32][..]).unwrap();
        let kp1 = generate_keypair_from_seed(seed);
        let kp2 = generate_keypair_from_seed(seed);

        assert_eq!(kp1.pk, kp2.pk);
    }

    #[test]
    fn different_seeds_different_keys() {
        let seed1 = <&Seed<XWingKem>>::try_from(&[1u8; 32][..]).unwrap();
        let seed2 = <&Seed<XWingKem>>::try_from(&[2u8; 32][..]).unwrap();

        assert_ne!(
            generate_keypair_from_seed(seed1).pk,
            generate_keypair_from_seed(seed2).pk
        );
    }

    #[test]
    fn seed_derived_pk_works_with_original_sk() {
        let kp = generate_keypair();
        let seed = <&Seed<XWingKem>>::try_from(&kp.sk[..]).unwrap();
        let derived = generate_keypair_from_seed(seed);
        let enc = encapsulate(&derived.pk).unwrap();
        let ss = decapsulate(&kp.sk, &enc.ciphertext);

        assert_eq!(enc.shared_key, *ss);
    }

    #[test]
    fn tampered_mlkem_part_wrong_shared_key() {
        let kp = generate_keypair();
        let enc = encapsulate(&kp.pk).unwrap();

        let mut ct = enc.ciphertext;
        ct[0] ^= 0x01;

        let ss = decapsulate(&kp.sk, &ct);

        assert_ne!(enc.shared_key, *ss);
    }

    #[test]
    fn tampered_x25519_part_wrong_shared_key() {
        let kp = generate_keypair();
        let enc = encapsulate(&kp.pk).unwrap();

        let mut ct = enc.ciphertext;
        ct[CIPHERTEXT_SIZE - 1] ^= 0x01;

        let ss = decapsulate(&kp.sk, &ct);

        assert_ne!(enc.shared_key, *ss);
    }
}

#[cfg(all(target_arch = "wasm32", test))]
mod wasm_tests {
    use super::wasm::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn wasm_roundtrip() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let enc = encapsulate(&kp.public_key).unwrap().to_rust().unwrap();
        let ss = decapsulate(&kp.secret_key, &enc.ciphertext).unwrap();

        assert_eq!(enc.shared_key, ss);
    }

    #[wasm_bindgen_test]
    fn wasm_different_keypairs_different_shared_keys() {
        let kp1 = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let kp2 = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let enc1 = encapsulate(&kp1.public_key).unwrap().to_rust().unwrap();
        let enc2 = encapsulate(&kp2.public_key).unwrap().to_rust().unwrap();

        assert_ne!(enc1.shared_key, enc2.shared_key);
    }

    #[wasm_bindgen_test]
    fn wasm_encapsulate_twice_different_ciphertext() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let enc1 = encapsulate(&kp.public_key).unwrap().to_rust().unwrap();
        let enc2 = encapsulate(&kp.public_key).unwrap().to_rust().unwrap();

        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        assert_ne!(enc1.shared_key, enc2.shared_key);
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_sk_wrong_shared_key() {
        let kp1 = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let kp2 = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let enc = encapsulate(&kp1.public_key).unwrap().to_rust().unwrap();
        let ss = decapsulate(&kp2.secret_key, &enc.ciphertext).unwrap();

        assert_ne!(enc.shared_key, ss);
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_pk_length() {
        assert!(encapsulate(&[0u8; 32]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_sk_length() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let enc = encapsulate(&kp.public_key).unwrap().to_rust().unwrap();

        assert!(decapsulate(&[0u8; 16], &enc.ciphertext).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_ct_length() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();

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
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();

        assert_eq!(kp.secret_key.len(), 32);
        assert_eq!(kp.public_key.len(), 1216);
    }

    #[wasm_bindgen_test]
    fn wasm_ciphertext_and_shared_key_sizes() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let enc = encapsulate(&kp.public_key).unwrap().to_rust().unwrap();

        assert_eq!(enc.ciphertext.len(), 1120);
        assert_eq!(enc.shared_key.len(), 32);
    }

    #[wasm_bindgen_test]
    fn rejects_wrong_seed_length() {
        assert!(generate_keypair_seed_wasm(&[0u8; 31]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_seed_roundtrip() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let derived = generate_keypair_seed_wasm(&kp.secret_key)
            .unwrap()
            .to_rust()
            .unwrap();

        assert_eq!(derived.secret_key, kp.secret_key);
        assert_eq!(derived.public_key, kp.public_key);
    }

    #[wasm_bindgen_test]
    fn wasm_seed_deterministic() {
        let seed = [7u8; 32];
        let kp1 = generate_keypair_seed_wasm(&seed)
            .unwrap()
            .to_rust()
            .unwrap();
        let kp2 = generate_keypair_seed_wasm(&seed)
            .unwrap()
            .to_rust()
            .unwrap();

        assert_eq!(kp1.public_key, kp2.public_key);
    }

    #[wasm_bindgen_test]
    fn wasm_different_seeds_different_keys() {
        let kp1 = generate_keypair_seed_wasm(&[1u8; 32])
            .unwrap()
            .to_rust()
            .unwrap();
        let kp2 = generate_keypair_seed_wasm(&[2u8; 32])
            .unwrap()
            .to_rust()
            .unwrap();

        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[wasm_bindgen_test]
    fn wasm_seed_derived_pk_works_with_original_sk() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let derived = generate_keypair_seed_wasm(&kp.secret_key)
            .unwrap()
            .to_rust()
            .unwrap();
        let enc = encapsulate(&derived.public_key).unwrap().to_rust().unwrap();
        let ss = decapsulate(&kp.secret_key, &enc.ciphertext).unwrap();

        assert_eq!(enc.shared_key, ss);
    }

    #[wasm_bindgen_test]
    fn wasm_seed_too_long() {
        assert!(generate_keypair_seed_wasm(&[0u8; 33]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_seed_empty() {
        assert!(generate_keypair_seed_wasm(&[]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_tampered_ciphertext_wrong_shared_key() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let enc = encapsulate(&kp.public_key).unwrap().to_rust().unwrap();

        let mut ct = enc.ciphertext.clone();
        ct[0] ^= 0x01;

        let ss = decapsulate(&kp.secret_key, &ct).unwrap();

        assert_ne!(enc.shared_key, ss);
    }

    #[wasm_bindgen_test]
    fn wasm_tampered_x25519_part_wrong_shared_key() {
        let kp = generate_keypair_wasm().unwrap().to_rust().unwrap();
        let enc = encapsulate(&kp.public_key).unwrap().to_rust().unwrap();

        let mut ct = enc.ciphertext.clone();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;

        let ss = decapsulate(&kp.secret_key, &ct).unwrap();

        assert_ne!(enc.shared_key, ss);
    }
}
