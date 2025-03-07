use pqc_dilithium::*;
use bytes::BytesMut;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::io::{self, AsyncWriteExt, AsyncReadExt};
use std::sync::Arc;
use ring::signature::KeyPair;

pub async fn request_main_nodes(dilithium_keys: &Keypair, ip: &str, port: u16, nonce: [u8; 16]) -> io::Result<Vec<String>> {
    let public_key = dilithium_keys.public.clone();
    let current_time = SystemTime::now();
    let duration_since_epoch = current_time.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let timestamp = duration_since_epoch.as_secs() as u64;
    let timestamp_bytes = timestamp.to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(public_key.len() + timestamp_bytes.len() + nonce.len());
    sign_part.extend_from_slice(&public_key);
    sign_part.extend_from_slice(&nonce);
    sign_part.extend_from_slice(&timestamp_bytes);

    let signature = dilithium_keys.sign(&sign_part);
    let signature_length = signature.len() as u16;

    let mut buffer = BytesMut::with_capacity(5 + signature.len() + sign_part.len());
    
    buffer.extend_from_slice(&[0x0a, 0x00, 0x00]);
    buffer.extend_from_slice(&signature_length.to_le_bytes());
    buffer.extend_from_slice(&signature);
    buffer.extend_from_slice(&sign_part);

    let total_size = buffer.len() as u16;
    buffer[1..3].copy_from_slice(&total_size.to_le_bytes());
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
    
    stream.write_all(&buffer).await?;

    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).await?;

    let ips_string = String::from_utf8_lossy(&response[3..n]);
    let ips: Vec<String> = ips_string.split_whitespace().map(|s| s.to_string()).collect();

    Ok(ips)
}

pub async fn connect(dilithium_keys: &Keypair, ed25519_keys: &ring::signature::Ed25519KeyPair, stream: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>, nonce: [u8; 16]) {
    let dilithium_public_key = dilithium_keys.public.clone();
    let ed25519_public_key = ed25519_keys.public_key().as_ref().to_vec();
    let current_time = SystemTime::now();
    let duration_since_epoch = current_time.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let timestamp = duration_since_epoch.as_secs() as u64;
    let timestamp_bytes = timestamp.to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(dilithium_public_key.len() + ed25519_public_key.len() + nonce.len() + timestamp_bytes.len());
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&nonce);
    sign_part.extend_from_slice(&timestamp_bytes);

    let dilithium_signature = dilithium_keys.sign(&sign_part);
    let ed25519_signature = ed25519_keys.sign(&sign_part).as_ref().to_vec();

    let mut buffer = BytesMut::with_capacity(5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len());
    
    buffer.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
    buffer.extend_from_slice(&dilithium_signature);
    buffer.extend_from_slice(&ed25519_signature);
    buffer.extend_from_slice(&sign_part);

    let total_size = buffer.len() as u16;
    buffer[1..3].copy_from_slice(&total_size.to_le_bytes());
    let mut stream = stream.lock().await;
    let _ = stream.write_all(&buffer).await;
}

pub async fn send_cyphertext(
    dilithium_keys: &pqc_dilithium::Keypair, 
    ed25519_keys: &ring::signature::Ed25519KeyPair,
    stream: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>,
    dst_id_bytes: Vec<u8>,
    cyphertext: Vec<u8>,
    nonce: [u8; 16],
) {
    let dilithium_public_key = dilithium_keys.public.clone();
    let ed25519_public_key = ed25519_keys.public_key().as_ref().to_vec();
    let current_time = SystemTime::now();
    let duration_since_epoch = current_time.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let timestamp = duration_since_epoch.as_secs() as u64;
    let timestamp_bytes = timestamp.to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(dilithium_public_key.len() + ed25519_public_key.len() + dst_id_bytes.len() + nonce.len() + timestamp_bytes.len() + cyphertext.len());
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&cyphertext);

    let dilithium_signature = dilithium_keys.sign(&sign_part);
    let ed25519_signature = ed25519_keys.sign(&sign_part).as_ref().to_vec();

    let mut buffer = BytesMut::with_capacity(5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len());
    
    buffer.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x00]);
    buffer.extend_from_slice(&dilithium_signature);
    buffer.extend_from_slice(&ed25519_signature);
    buffer.extend_from_slice(&sign_part);

    let total_size = buffer.len() as u16;
    buffer[1..3].copy_from_slice(&total_size.to_le_bytes());
    
    let mut stream = stream.lock().await;
    let _ = stream.write_all(&buffer).await;
    println!("Sent Cyphertext");
}

