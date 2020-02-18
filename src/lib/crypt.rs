use rand::Rng;
use cfb_mode::Cfb;
use des::Des;
use cfb_mode::stream_cipher::{NewStreamCipher, StreamCipher};

type DesCfb = Cfb<Des>;

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