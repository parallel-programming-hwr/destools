use rand::Rng;
use cfb_mode::Cfb;
use des::Des;
use cfb_mode::stream_cipher::{NewStreamCipher, StreamCipher};
use rayon::prelude::*;
use crate::lib::hash::{PassKey, sha_checksum};

type DesCfb = Cfb<Des>;

pub struct EncryptionKeys {
    current: u64
}

impl Iterator for EncryptionKeys {
    type Item = Vec<u8>;

    /// Increases the stored number by one
    fn next(&mut self) -> Option<Self::Item> {
        if self.current < std::u64::MAX {
            self.current += 1;
            Some(self.current.to_be_bytes().to_vec())
        } else {
            None
        }
    }
}

impl EncryptionKeys {
    pub fn new() -> Self {
        Self {
            current: 0
        }
    }
}

/// Encrypts data with des
pub fn encrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = rand::thread_rng().gen::<[u8; 8]>();
    let mut buffer = data.to_vec();
    let mut cipher = DesCfb::new_var(key, &iv).unwrap();
    cipher.encrypt(&mut buffer);
    let mut cipher_text = iv.to_vec();
    cipher_text.append(&mut buffer.to_vec());
    return cipher_text;
}

/// Decrypts data with des
pub fn decrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = &data[..8];
    let mut buffer = data[8..].to_vec();
    let mut cipher = DesCfb::new_var(&key, &iv).unwrap();
    cipher.decrypt(&mut buffer);
    return buffer;
}

/// Decrypts data using a dictionary
pub fn decrypt_with_dictionary(data: &[u8], dict: Vec<PassKey>, checksum: &[u8]) -> Option<Vec<u8>> {
    let pass = dict.par_iter().find_first(|(_pw, key)| {
        let decrypted_data = decrypt_data(&data, key);
        let decr_check = sha_checksum(&decrypted_data);
        if decr_check == checksum {
            true
        } else {
            false
        }
    });
    if let Some((pw, key)) = pass {
        println!("Password found: {}", pw);
        Some(decrypt_data(data, &key))
    } else {
        None
    }
}

/// Decrypts data by generating all possible keys
pub fn decrypt_brute_brute_force(data: &[u8], checksum: &[u8]) -> Option<Vec<u8>> {
    let encryption_key = (0u64..std::u64::MAX).into_par_iter().find_first(|num: &u64| {
        let key: &[u8] = &num.to_le_bytes();
        let decrypted_data = decrypt_data(&data, key);
        let decr_check = sha_checksum(&decrypted_data);
        if decr_check == checksum {
            true
        } else {
            false
        }
    });
    if let Some(num) = encryption_key {
        let key: &[u8] = &num.to_le_bytes();
        println!("Key found: {:?}", key);
        Some(decrypt_data(data, key))
    } else {
        None
    }
}