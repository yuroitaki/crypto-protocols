# Cryptography Protocols
A Rust implementation of multiple cryptography protocols. Currently the following has been implemented:
- RSA

## RSA
### Features
- Private and public keys generation (2048/4096 bits)
- Encryption using public key with the option of using custom encoding (e.g. hex)
- Decryption using private key with the option of using custom decoding (e.g. hex)

### Notes
- Euler totient function `φ(n) = (p − 1)(q − 1)` is used to calculate private exponent `d`

### Examples
```rust
use crypto_protocols::rsa::{
    domain::RSAType,
    error::RSAError,
    key::RSAPrivateKey,
};

let private_key = RSAPrivateKey::new(RSAType::RSA2048).unwrap();
let public_key = private_key.to_public_key();

let message = "Satoshi Nakamoto";
let encoding_func: Option<fn(Vec<u8>) -> String> = None;
let ciphertext = public_key.encrypt(message, encoding_func).unwrap();

let decoding_func: Option<fn(String) -> Result<Vec<u8>, RSAError>> = None;
let decrypted_message = private_key.decrypt(ciphertext, decoding_func).unwrap();

assert_eq!(message, decrypted_message);
```
