mod rsa;

use rsa::{
    domain::RSAType,
    lib::RSAPrivateKey,
};

fn main() {
    let private_key = match RSAPrivateKey::new(RSAType::RSA2048) {
        Ok(key) => key,
        Err(err) => panic!("{:?}", err),
    };
    let public_key = private_key.public_key();
    let message = "Satoshi Nakamoto is the name used by the presumed pseudonymous[1][2][3][4] person or persons who developed bitcoin, authored the bitcoin white paper, and created and deployed bitcoin's original reference implementation.[5] As part of the implementation, Nakamoto also devised the first blockchain database.[6]".to_string();
    println!("Message: {}", message);
    let ciphertext = public_key.encrypt(&message);
    println!("Ciphertext: {:?}", ciphertext);
    let decrypted_message = match private_key.decrypt(&ciphertext) {
        Ok(msg) => msg,
        Err(err) => panic!("{:?}", err),
    };
    println!("Decrypted message: {}", decrypted_message);
}
