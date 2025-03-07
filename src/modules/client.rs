use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, split};
use std::sync::Arc;
use tokio::sync::Mutex;
use bytes::BytesMut;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::signature::KeyPair;
use super::tcp;


pub struct Message {
    pub sender: String,
    pub content: String,
}



pub struct Client
{
    dilithium_keys: pqc_dilithium::Keypair,
    ed25519_keys: ring::signature::Ed25519KeyPair,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>,
    reader: Arc<tokio::sync::Mutex<tokio::io::ReadHalf<tokio::net::TcpStream>>>,
    shared_secrets: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    nonce: [u8; 16],
}

impl Client
{
    pub async fn new(ip: &str, port: u16) -> std::io::Result<Self> {
        let (dilithium_keys, ed25519_keys, nonce) = super::keys::generate_keypairs().await;
        let stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
        // Split the stream into read and write halves
        let (read_half, write_half) = split(stream);
        
        let read_half = Arc::new(Mutex::new(read_half));
        let write_half = Arc::new(Mutex::new(write_half));
        
        let shared_secrets = Arc::new(Mutex::new(HashMap::new()));
        tcp::connect(&dilithium_keys, &ed25519_keys, Arc::clone(&write_half), nonce).await;
        Ok(Self {
            writer: write_half,
            reader: read_half,
            dilithium_keys,
            ed25519_keys,
            shared_secrets,
            nonce,
        })
    }
    

    pub async fn listen<F>(&self, on_message: F)
    where
        F: Fn(Message) + Send + Sync + 'static,
    {
        let mut buffer = BytesMut::with_capacity(1024);
        let mut chunk = vec![0u8; 1024];

        loop {
            let mut locked_stream = self.reader.lock().await;
            match locked_stream.read(&mut chunk).await {
                Ok(0) => {
                    println!("Disconnected from server.");
                    break;
                }
                Ok(n) => {
                    drop(locked_stream);
                    buffer.extend_from_slice(&chunk[..n]);

                    if buffer.len() < 3 {
                        println!("[ERROR] Invalid packet: too short");
                        buffer.clear();
                        continue;
                    }

                    let prefix = buffer[0];
                    let payload_size_bytes = &buffer[1..3];
                    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;
                    if buffer.len() < payload_size {
                        continue;
                    }
                    match prefix {
                        2 => {
                            super::handle::handle_kyber(&self.dilithium_keys, &self.ed25519_keys, Arc::clone(&self.writer), &buffer, Arc::clone(&self.shared_secrets), self.nonce).await;
                        }
                        4 => {
                            if let Some(message) = super::handle::handle_message(&buffer, Arc::clone(&self.shared_secrets)).await {
                                (on_message)(message);
                            }
                        }
                        _ => {
                            println!("[ERROR] Invalid packet: unknown prefix {}", prefix);
                        }
                    }

                    buffer.clear();
                    println!("Buffer cleared");
                }
                Err(e) => {
                    eprintln!("Error reading from stream: {:?}", e);
                    break;
                }
            }
        }
    }

    pub async fn send_message(&self, dst_id_hexs: &String, message_string: String) {
        let mut stream = self.writer.lock().await;
        let dst_id_bytes = hex::decode(dst_id_hexs).unwrap();
        let shared_secret = {
            let shared_secret_locked = self.shared_secrets.lock().await;
            shared_secret_locked.get(dst_id_hexs).unwrap().clone()
        };
        let message = super::encryption::encrypt_message(&message_string, &shared_secret).await;

        let dilithium_public_key = self.dilithium_keys.public.clone();
        let ed25519_public_key = self.ed25519_keys.public_key().as_ref().to_vec();

        let current_time = SystemTime::now();
        let duration_since_epoch = current_time.duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
    
        let timestamp = duration_since_epoch.as_secs() as u64;
        let timestamp_bytes = timestamp.to_le_bytes();
    
        let mut sign_part = BytesMut::with_capacity(dilithium_public_key.len() + ed25519_public_key.len() + dst_id_bytes.len() + self.nonce.len() + timestamp_bytes.len() + message.len());
        sign_part.extend_from_slice(&dilithium_public_key);
        sign_part.extend_from_slice(&ed25519_public_key);
        sign_part.extend_from_slice(&dst_id_bytes);
        sign_part.extend_from_slice(&self.nonce);
        sign_part.extend_from_slice(&timestamp_bytes);
        sign_part.extend_from_slice(&message);
    
        let dilithium_signature = self.dilithium_keys.sign(&sign_part);
        let ed25519_signature = self.ed25519_keys.sign(&sign_part).as_ref().to_vec();
    
        let mut buffer = BytesMut::with_capacity(5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len());
    
        buffer.extend_from_slice(&[0x04, 0x00, 0x00, 0x00, 0x00]);
        buffer.extend_from_slice(&dilithium_signature);
        buffer.extend_from_slice(&ed25519_signature);
        buffer.extend_from_slice(&sign_part);
    
        let total_size = buffer.len() as u16;
        buffer[1..3].copy_from_slice(&total_size.to_le_bytes());
        let _ = stream.write_all(&buffer).await;
        println!("Message sent");
    }
    
}
