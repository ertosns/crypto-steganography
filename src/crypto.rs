use anyhow::{Result, anyhow};
use std::fs;
use std::io::{Read, Cursor};
use pgp::{Deserializable, Message, SignedPublicKey, SignedSecretKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::CompressionAlgorithm;

pub fn encrypt_data(data: &[u8], public_key_path: &str) -> Result<Vec<u8>> {
    let mut key_file = fs::File::open(public_key_path)?;
    let mut key_data = Vec::new();
    key_file.read_to_end(&mut key_data)?;
    
    let mut cursor = Cursor::new(key_data);
    let (public_key, _) = SignedPublicKey::from_armor_single(&mut cursor)
        .map_err(|e| anyhow!("Failed to parse public key: {}", e))?;
    
    let literal_msg = Message::new_literal_bytes("data.bin", data);
    let compressed = literal_msg.compress(CompressionAlgorithm::ZLIB)
        .map_err(|e| anyhow!("Compression failed: {}", e))?;
    let encrypted_msg = compressed.encrypt_to_keys(&mut rand::thread_rng(), SymmetricKeyAlgorithm::AES256, &[&public_key])
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    
    let encrypted_bytes = encrypted_msg.to_bytes()
        .map_err(|e| anyhow!("Failed to serialize encrypted message: {}", e))?;
    
    Ok(encrypted_bytes)
}

pub fn decrypt_data(encrypted_data: &[u8], private_key_path: &str, passphrase: Option<&str>) -> Result<Vec<u8>> {
    let mut key_file = fs::File::open(private_key_path)?;
    let mut key_data = Vec::new();
    key_file.read_to_end(&mut key_data)?;
    
    let mut cursor = Cursor::new(key_data);
    let (secret_key, _) = SignedSecretKey::from_armor_single(&mut cursor)
        .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
    
    let message = Message::from_bytes(encrypted_data)
        .map_err(|e| anyhow!("Failed to parse encrypted message: {}", e))?;
    
    let (decrypter, _) = if let Some(pass) = passphrase {
        message.decrypt(|| pass.to_string(), &[&secret_key])
            .map_err(|e| anyhow!("Decryption failed: {}", e))?
    } else {
        message.decrypt(|| String::new(), &[&secret_key])
            .map_err(|e| anyhow!("Decryption failed (passphrase may be required): {}", e))?
    };
    
    let decrypted_msgs: Vec<_> = decrypter.collect();
    
    if decrypted_msgs.is_empty() {
        return Err(anyhow!("No decrypted messages found"));
    }
    
    let msg = &decrypted_msgs[0].as_ref()
        .map_err(|e| anyhow!("Failed to get decrypted message: {}", e))?;
    
    let decrypted_data = msg.get_content()
        .map_err(|e| anyhow!("Failed to get decrypted content: {}", e))?
        .unwrap_or_default();
    
    Ok(decrypted_data)
}
