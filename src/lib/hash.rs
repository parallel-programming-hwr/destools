use rayon::prelude::*;
use sha2::{Digest, Sha256};

pub type PassKey = (String, Vec<u8>);

/// Hashes a text to a 32 bytes long key.
pub fn create_key(pw: String) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(pw);
    let result = hasher.result();
    let key = &result[0..8];

    key.to_vec()
}

/// Maps a list of passwords to keys and returns a vector of pairs
pub fn map_to_keys(passwords: Vec<String>) -> Vec<PassKey> {
    passwords
        .par_iter()
        .map(|pw| {
            let pw_str = (*pw).clone();
            (pw_str.clone(), create_key(pw_str))
        })
        .collect()
}

/// Creates a sha256 hashsum from the input data
pub fn sha_checksum(data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(data);
    let result = hasher.result();

    result.to_vec()
}
