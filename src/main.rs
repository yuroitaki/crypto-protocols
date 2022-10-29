mod rsa;

use eyre::Result;
use rsa::{
    domain::RSAType,
    key::RSAPrivateKey,
};

fn main() -> Result<()> {
    let private_key = RSAPrivateKey::new(RSAType::RSA2048)?;
    let public_key = private_key.public_key();
    let message = "123450".to_string();
    println!("Message: {}", message);
    let ciphertext = public_key.encrypt(&message)?;
    println!("Ciphertext: {}", ciphertext);
    let decrypted_message = private_key.decrypt(&ciphertext)?;
    println!("Decrypted message: {}", decrypted_message);
    Ok(())
}
