use hmac::crypto_mac::InvalidKeyLength;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub type PassKey = (String, Vec<u8>);
type HmacSha256 = Hmac<Sha256>;

/// Hashes a text to a 32 bytes long key.
pub fn create_key(pw: &str) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(pw);
    let result = hasher.result();
    let key = &result[0..8];

    key.to_vec().clone()
}

/// Hashes a text to a sha256.
pub fn sha256(pw: &str) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(pw);
    let result = hasher.result();

    result.to_vec()
}

/// Creates a sha256 hashsum from the input data
pub fn sha_checksum(data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(data);
    let result = hasher.result();

    result.to_vec()
}

/// Creates a hmac hash to be appended after the encrypted message
pub fn create_hmac(key: &Vec<u8>, data: &Vec<u8>) -> Result<Vec<u8>, InvalidKeyLength> {
    let mut mac = HmacSha256::new_varkey(key)?;
    mac.input(data);

    Ok(mac.result().code().to_vec())
}
