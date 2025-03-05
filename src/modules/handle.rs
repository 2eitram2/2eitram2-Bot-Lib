use super::{tcp, utils, encryption};
use bytes::BytesMut;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::TcpStream;
use std::collections::HashMap;

pub async fn handle_kyber(
    keys: &pqc_dilithium::Keypair, 
    stream: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>,
    buffer: &BytesMut,
    shared_secrets: Arc<Mutex<HashMap<String, Vec<u8>>>>
) {
    let mut rng = rand::thread_rng();
    let signature_length_bytes = &buffer[3..5];
    let signature_length = u16::from_le_bytes([signature_length_bytes[0], signature_length_bytes[1]]) as usize; 
    let dilihium_pub_key = &buffer[signature_length + 5 .. signature_length + 5 + 1952];
    let public_key = &buffer[signature_length + 1952 + 5 + 32 + 8 .. signature_length + 1952 + 5 + 32 + 8 + 1568];

    let (ciphertext, shared_secret) = pqc_kyber::encapsulate(&public_key, &mut rng).unwrap();
    let dst_id_hex = utils::sha256_hash(&dilihium_pub_key);
    let mut locked_shared_secrets = shared_secrets.lock().await;
    locked_shared_secrets.insert(dst_id_hex.clone(), shared_secret.to_vec());
    let dst_id_bytes = hex::decode(dst_id_hex).unwrap();
    tcp::send_cyphertext(
        keys,
        stream,
        dst_id_bytes,
        ciphertext.to_vec(),
    ).await;
}

pub async fn handle_message(buffer: &BytesMut, shared_secrets: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> Option<super::client::Message> {
    let signature_length_bytes = &buffer[3..5];
    let signature_length = u16::from_le_bytes([signature_length_bytes[0], signature_length_bytes[1]]) as usize;

    let dilithium_pub_key = &buffer[signature_length + 5..signature_length + 5 + 1952];
    let dst_id_hex = utils::sha256_hash(&dilithium_pub_key);

    let locked_shared_secrets = shared_secrets.lock().await;
    let shared_secret = match locked_shared_secrets.get(&dst_id_hex) {
        Some(secret) => secret.clone(),
        None => {
            println!("[ERROR] No shared secret found for {}", dst_id_hex);
            return None;
        }
    };

    match encryption::decrypt_message(
        &buffer[signature_length + 1952 + 5 + 32 + 8..].to_vec(),
        &shared_secret.to_vec(),
    ).await {
        Ok(decrypted_message) => Some(super::client::Message {
            sender: dst_id_hex,
            content: decrypted_message,
        }),
        Err(e) => {
            println!("[ERROR] Decryption failed: {:?}", e);
            None
        }
    }
}

