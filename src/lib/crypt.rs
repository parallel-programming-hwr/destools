use crate::lib::hash::{sha_checksum, PassKey};
use cfb_mode::stream_cipher::{NewStreamCipher, StreamCipher};
use cfb_mode::Cfb;
use des::Des;
use rand::Rng;
use rayon::prelude::*;
use std::sync::Mutex;

type DesCfb = Cfb<Des>;

/// Encrypts data with des
pub fn encrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = rand::thread_rng().gen::<[u8; 8]>();
    let mut buffer = data.to_vec();
    let mut cipher = DesCfb::new_var(key, &iv).unwrap();
    cipher.encrypt(&mut buffer);
    let mut cipher_text = iv.to_vec();
    cipher_text.append(&mut buffer.to_vec());

    cipher_text
}

/// Decrypts data with des
pub fn decrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = &data[..8];
    let mut buffer = data[8..].to_vec();
    let mut cipher = DesCfb::new_var(&key, &iv).unwrap();
    cipher.decrypt(&mut buffer);

    buffer
}

/// Decrypts data using a dictionary
pub fn decrypt_with_dictionary(
    data: &[u8],
    dict: Vec<PassKey>,
    checksum: &[u8],
) -> Option<Vec<u8>> {
    let decrypted = Mutex::<Option<Vec<u8>>>::new(None);
    let pass = dict.par_iter().find_first(|(_pw, key)| {
        let decrypted_data = decrypt_data(&data, key);
        let decr_check = sha_checksum(&decrypted_data);
        return if decr_check == checksum {
            let mut decry = decrypted.lock().unwrap();
            *decry = Some(decrypted_data);
            true
        } else {
            false
        };
    });
    if let Some((pw, _key)) = pass {
        println!("\nPassword found: {}", pw);
        let decry = decrypted.lock().unwrap();
        if let Some(decrypted_data) = (*decry).clone() {
            return Some(decrypted_data);
        }
    }
    None
}

/// Decrypts data by generating all possible keys
pub fn decrypt_brute_brute_force(data: &[u8], checksum: &[u8]) -> Option<Vec<u8>> {
    let encryption_key = (0u64..std::u64::MAX)
        .into_par_iter()
        .find_first(|num: &u64| {
            let key: &[u8] = &num.to_le_bytes();
            let decrypted_data = decrypt_data(&data, key);
            let decr_check = sha_checksum(&decrypted_data);

            decr_check == checksum
        });
    if let Some(num) = encryption_key {
        let key: &[u8] = &num.to_le_bytes();
        println!("Key found: {:?}", key);

        return Some(decrypt_data(data, key));
    }
    None
}
