use crate::rsa::{
    domain::RSAType,
    error::RSAError,
    util::modular_inverse,
};

use eyre::Result;
use glass_pumpkin::prime;
use hex::{decode, encode};
use num_bigint::BigUint;
use num_traits::One;
use rand::rngs::OsRng;

const EXPONENT: u64 = 65537;

#[derive(Clone, Debug)]
pub struct RSAPublicKey {
    modulus: BigUint,
    public_exponent: BigUint,
}

impl RSAPublicKey {
    fn new(modulus: BigUint, public_exponent: BigUint) -> Self {
        Self {
            modulus,
            public_exponent,
        }
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, RSAError> {
        let plaintext_bytes = plaintext.as_bytes();
        let plaintext_number = BigUint::from_bytes_be(plaintext_bytes);
        if plaintext_number.bits() > self.modulus.bits() {
            return Err(RSAError::MessageSizeLimitExceeded(
                format!(
                    "Message bit size: {} exceeds modulus bit size: {}",
                    plaintext_number.bits(),
                    self.modulus.bits(),
                )
            ));
        }
        let ciphertext_number = plaintext_number.modpow(
            &self.public_exponent,
            &self.modulus
        );
        let ciphertext_bytes = ciphertext_number.to_bytes_be();
        let ciphertext = encode(ciphertext_bytes);
        Ok(ciphertext)
    }
}

#[derive(Clone, Debug)]
pub struct RSAPrivateKey {
    public_key: RSAPublicKey,
    private_exponent: BigUint,
}

impl RSAPrivateKey {
    pub fn new(rsa_type: RSAType) -> Result<Self, RSAError> {
        let bits = match rsa_type {
            RSAType::RSA2048 => 1024,
            RSAType::RSA4096 => 2048,
        };
        let mut rng = OsRng;
        let first_prime = prime::from_rng(bits, &mut rng)?;
        let second_prime = prime::from_rng(bits, &mut rng)?;
        let modulus = first_prime.clone() * second_prime.clone();
        let totient = (first_prime - BigUint::one()) * (second_prime - BigUint::one());
        let public_exponent = BigUint::from(EXPONENT);
        let priv_exp = modular_inverse(
            &public_exponent.clone().into(),
            &totient.into()
        );
        let private_exponent = BigUint::try_from(priv_exp)?;
        Ok(Self {
            public_key: RSAPublicKey::new(modulus, public_exponent),
            private_exponent,
        })
    }

    pub fn public_key(&self) -> RSAPublicKey {
        self.public_key.clone()
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String, RSAError> {
        let ciphertext_bytes = decode(ciphertext)?;
        let ciphertext_number = BigUint::from_bytes_be(&ciphertext_bytes);
        let plaintext_number = ciphertext_number.modpow(
            &self.private_exponent,
            &self.public_key.modulus,
        );
        let plaintext_bytes = plaintext_number.to_bytes_be();
        let plaintext = String::from_utf8_lossy(&plaintext_bytes).to_string();
        Ok(plaintext)
    }
}
