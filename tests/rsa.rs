use crypto_protocols::rsa::{
    domain::RSAType,
    error::RSAError,
    key::RSAPrivateKey
};
use eyre::Result;

#[test]
fn test_encrypt_and_decrypt() -> Result<()> {
    let private_key = RSAPrivateKey::new(RSAType::RSA2048)?;
    let public_key = private_key.to_public_key();
    let message = "Satoshi Nakamoto";
    let encoding_func: Option<fn(Vec<u8>) -> String> = None;
    let ciphertext = public_key.encrypt(message, encoding_func)?;
    let decoding_func: Option<fn(String) -> Result<Vec<u8>, RSAError>> = None;
    let decrypted_message = private_key.decrypt(ciphertext, decoding_func)?;
    assert_eq!(message, decrypted_message);
    Ok(())
}

#[test]
fn test_encrypt_and_decrypt_with_encoding_decoding_func() -> Result<()> {
    let private_key = RSAPrivateKey::new(RSAType::RSA2048)?;
    let public_key = private_key.to_public_key();
    let message = 12345;
    let encoding_func: Option<fn(Vec<u8>) -> String> = Some(hex::encode);
    let ciphertext = public_key.encrypt(message, encoding_func)?;
    let decoding_func: Option<fn(String) -> Result<Vec<u8>, hex::FromHexError>> = Some(hex::decode);
    let decrypted_message = private_key.decrypt(ciphertext, decoding_func)?;
    assert_eq!(message.to_string(), decrypted_message);
    Ok(())
}

#[test]
#[should_panic]
fn test_message_size_exceeds_limit() {
    let private_key = RSAPrivateKey::new(RSAType::RSA2048).unwrap();
    let public_key = private_key.to_public_key();
    let message = "Satoshi Nakamoto is the name used by the presumed pseudonymous[1][2][3][4] person or persons who developed bitcoin, authored the bitcoin white paper, and created and deployed bitcoin's original reference implementation.[5] As part of the implementation, Nakamoto also devised the first blockchain database.[6]";
    let encoding_func: Option<fn(Vec<u8>) -> String> = None;
    let _ = public_key.encrypt(message, encoding_func).unwrap();
}
