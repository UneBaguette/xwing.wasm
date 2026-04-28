# xwing-wasm

**X-Wing** hybrid KEM ([ML-KEM-768](https://csrc.nist.gov/pubs/fips/203/final) + [X25519](https://www.rfc-editor.org/info/rfc7748)) with WASM bindings. 

Built in Rust on [`x-wing`](https://github.com/RustCrypto/KEMs/tree/master/x-wing).

**X-Wing** is a post-quantum/traditional hybrid **key encapsulation mechanism**. If either **X25519** or **ML-KEM-768** remains secure, **X-Wing** remains secure.

## Install

```bash
npm install xwing-wasm
```

## Usage

```ts
import { generateKeypair, encapsulate, decapsulate } from 'xwing-wasm';

// Generate keypair (32-byte secret key + 1216-byte public key)
const { secretKey, publicKey } = generateKeypair();

// Encapsulate: produce shared key + ciphertext from public key
const { sharedKey, ciphertext } = encapsulate(publicKey);

// Decapsulate: recover shared key from secret key + ciphertext
const recoveredKey = decapsulate(secretKey, ciphertext);

// sharedKey === recoveredKey
```

## Sizes

| Value                      | Size        |
|----------------------------|-------------|
| Secret key (decapsulation) | 32 bytes    |
| Public key (encapsulation) | 1,216 bytes |
| Ciphertext                 | 1,120 bytes |
| Shared key                 | 32 bytes    |

## Native Rust usage

```rust
use xwing_wasm_rs::*;

let kp = generate_keypair();
let enc = encapsulate(&kp.pk).unwrap();
let ss = decapsulate(&kp.sk, &enc.ciphertext);

assert_eq!(enc.shared_key, *ss);
```

## Security

- Secret key and shared key **zeroized** on drop
- Decapsulate returns `Zeroizing<[u8; 32]>` for automatic cleanup
- Based on [`x-wing`](https://crates.io/crates/x-wing) by **RustCrypto** (unaudited)
- Reference: [X-Wing: The Hybrid KEM You've Been Looking For](https://eprint.iacr.org/2024/039)

## License

Dual-licensed under the [MIT License](LICENSE-MIT) or [Apache-2.0 License](LICENSE-APACHE).