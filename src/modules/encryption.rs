use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};
use aes_gcm::AeadCore;
use rand::rngs::OsRng;

pub async fn decrypt_message(
    encrypted_buffer: &Vec<u8>,
    key_buffer: &Vec<u8>,
) -> Result<String, String> {
    // Ensure the encrypted buffer has at least 12 bytes (IV size)
    if encrypted_buffer.len() < 12 {
        return Err("Encrypted buffer is too short".to_string());
    }

    // Slice the encrypted message
    let iv = &encrypted_buffer[0..12]; // Extract the IV (first 12 bytes)
    let cipher_text_buffer = &encrypted_buffer[12..]; // The rest is the ciphertext

    // Import the key (AES-GCM expects a 256-bit key)
    let key = Key::<Aes256Gcm>::from_slice(&key_buffer);

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(&key);

    // Create nonce from IV
    let nonce = Nonce::from_slice(iv);

    // Try to decrypt the message
    match cipher.decrypt(nonce, cipher_text_buffer.as_ref()) {
        Ok(result) => match String::from_utf8(result) {
            Ok(text) => {
                let cleaned_text = text.replace("&nbsp;", " ");
                Ok(cleaned_text)
            }
            Err(e) => Err(format!("UTF-8 conversion error: {}", e)),
        },
        Err(e) => Err(format!("Decryption failed: {:?}", e)),
    }
}

pub async fn encrypt_message(plain_text: &str, key_buffer: &Vec<u8>) -> Vec<u8> {
    // Generate a random IV (Nonce) - 12 bytes for AES-GCM
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 

    // Import the key
    let key = Key::<Aes256Gcm>::from_slice(&key_buffer);

    // Create AES-GCM cipher
    let cipher = Aes256Gcm::new(&key);

    // Encrypt the message
    match cipher.encrypt(&nonce, plain_text.as_bytes()) {
        Ok(mut encrypted_data) => {
            // Prepend the IV to the encrypted data
            let mut result = nonce.to_vec();
            result.append(&mut encrypted_data);
            result
        }
        Err(e) => {
            println!("Error encrypting message: {:?}", e);
            Vec::new() // Return empty vector on failure
        }
    }
}