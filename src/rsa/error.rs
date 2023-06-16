use glass_pumpkin;
use hex::FromHexError;
use num_bigint::{BigInt, TryFromBigIntError};
use std::{error::Error, fmt};

#[derive(Clone, Debug)]
pub enum RSAError {
    PrimeNumberGenerationFailed(String),
    ConvertBigUIntToBigIntFailed(String),
    ConvertCipherToHexFailed(String),
    MessageSizeLimitExceeded(String),
}

impl From<glass_pumpkin::error::Error> for RSAError {
    fn from(err: glass_pumpkin::error::Error) -> RSAError {
        RSAError::PrimeNumberGenerationFailed(format!(
            "Failed to generate large prime number: {}",
            err
        ))
    }
}

impl From<TryFromBigIntError<BigInt>> for RSAError {
    fn from(err: TryFromBigIntError<BigInt>) -> RSAError {
        RSAError::ConvertBigUIntToBigIntFailed(format!(
            "Failed to convert to BigUInt from BigInt: {}",
            err
        ))
    }
}

impl From<FromHexError> for RSAError {
    fn from(err: FromHexError) -> RSAError {
        RSAError::ConvertCipherToHexFailed(format!(
            "Failed to convert to ciphertext from hex for decoding: {}",
            err
        ))
    }
}

impl fmt::Display for RSAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for RSAError {}
