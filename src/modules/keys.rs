use pqc_dilithium::*;
use super::utils;

pub async fn generate_keypair() -> Keypair {
    loop {
        let keys = Keypair::generate();
        let public_id = utils::sha256_hash(&keys.public);

        if !public_id.starts_with("0") {
            continue;
        }
        println!("Generated Public Id: {}", public_id);
        return keys;
    }
}