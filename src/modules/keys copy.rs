use pqc_dilithium::*;
use super::utils;
use ring;
use rand::Rng;

fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill(&mut nonce);
    nonce
}

pub async fn generate_keypairs() -> (pqc_dilithium::Keypair, ring::signature::Ed25519KeyPair, [u8; 16]) {
    loop {
        let rng = ring::rand::SystemRandom::new();
        let ed25519_keys =  ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keypair generation failed");
        let ed25519_keys = ring::signature::Ed25519KeyPair::from_pkcs8(ed25519_keys.as_ref()).expect("keypair parsing failed");
        let dilithium_keys = Keypair::generate();
        let public_id = utils::sha256_hash(&dilithium_keys.public);
        let nonce = generate_nonce();

        if !public_id.starts_with("0") {
            continue;
        }

        println!("Generated Public Id: {}", public_id);
        return (dilithium_keys, ed25519_keys, nonce);
    }
}