use pqc_dilithium::*;
use super::utils;
use ring;
use rand::Rng;
use ring::signature::KeyPair;

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
        let ed25519_public_key = ed25519_keys.public_key().as_ref().to_vec();

        let nonce = generate_nonce();
        let full_hash_input = [
            &dilithium_keys.public[..],
            &ed25519_public_key[..],         
            &nonce[..],                      
        ].concat();
        let public_id = utils::sha256_hash(&full_hash_input);
        if !public_id.starts_with("0") {
            continue;
        }

        println!("Generated Public Id: {}", public_id);
        return (dilithium_keys, ed25519_keys, nonce);
    }
}