use super::{tcp, utils, encryption};
use bytes::BytesMut;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;

pub async fn handle_kyber(
    dilithium_keys: &pqc_dilithium::Keypair, 
    ed25519_keys: &ring::signature::Ed25519KeyPair,
    stream: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>,
    buffer: &BytesMut,
    shared_secrets: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    nonce: [u8; 16],
) {
    let mut rng = rand::thread_rng();

    let dilihium_pub_key = &buffer[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let kyber_public_key = &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 1568];

    let full_hash_input = [
        &dilihium_pub_key[..],
        &ed25519_public_key[..],         
        &src_id_nonce[..],                      
    ].concat();

    let (ciphertext, shared_secret) = pqc_kyber::encapsulate(&kyber_public_key, &mut rng).unwrap();
    let dst_id_hex = utils::sha256_hash(&full_hash_input);
    println!("{}", &dst_id_hex);
    let mut locked_shared_secrets = shared_secrets.lock().await;
    locked_shared_secrets.insert(dst_id_hex.clone(), shared_secret.to_vec());
    let dst_id_bytes = hex::decode(dst_id_hex).unwrap();

    tcp::send_cyphertext(
        dilithium_keys,
        ed25519_keys,
        stream,
        dst_id_bytes,
        ciphertext.to_vec(),
        nonce,
        
    ).await;
}

pub async fn handle_message(buffer: &BytesMut, shared_secrets: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> Option<super::client::Message> {

    let dilithium_pub_key = &buffer[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_pub_key = &buffer[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16];

    let full_hash_input = [
        &dilithium_pub_key[..],
        &ed25519_pub_key[..],         
        &src_id_nonce[..],                      
    ].concat();

    let dst_id_hex = utils::sha256_hash(&full_hash_input);
    println!("{}", dst_id_hex);

    let locked_shared_secrets = shared_secrets.lock().await;
    let shared_secret = match locked_shared_secrets.get(&dst_id_hex) {
        Some(secret) => secret.clone(),
        None => {
            println!("[ERROR] No shared secret found for {}", dst_id_hex);
            return None;
        }
    };

    match encryption::decrypt_message(
        &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..].to_vec(),
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

