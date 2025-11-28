use image::GenericImageView;
use anyhow::{Result, anyhow};
use std::fs;
use std::io::Write;

use crate::crypto;

const END_MARKER: &str = "###END###";
const FILE_MARKER: &str = "###FILE##";

pub fn decode_text(input_path: &str, gpg_key: Option<&str>, passphrase: Option<&str>) -> Result<String> {
    let img = image::open(input_path)?;
    let (width, height) = img.dimensions();
    let img_rgba = img.to_rgba8();
    
    let mut bits = Vec::new();
    let mut bytes = Vec::new();
    
    for y in 0..height {
        for x in 0..width {
            let pixel = img_rgba.get_pixel(x, y);
            
            for channel in 0..3 {
                let bit = pixel[channel] & 1;
                bits.push(bit);
                
                if bits.len() == 8 {
                    let mut byte = 0u8;
                    for (i, &bit) in bits.iter().enumerate() {
                        byte |= bit << (7 - i);
                    }
                    bytes.push(byte);
                    bits.clear();
                    
                    if bytes.len() >= END_MARKER.len() {
                        let potential_message = String::from_utf8_lossy(&bytes);
                        if potential_message.ends_with(END_MARKER) {
                            let message_bytes = &bytes[..bytes.len() - END_MARKER.len()];
                            
                            if let Some(key_path) = gpg_key {
                                let decrypted = crypto::decrypt_data(message_bytes, key_path, passphrase)?;
                                let message = String::from_utf8(decrypted)
                                    .map_err(|e| anyhow!("Failed to decode decrypted message as UTF-8: {}", e))?;
                                return Ok(message);
                            } else {
                                let message = String::from_utf8_lossy(message_bytes).to_string();
                                return Ok(message);
                            }
                        }
                    }
                }
            }
        }
    }
    
    Err(anyhow!("No valid message found in image"))
}

pub fn decode_file(input_path: &str, output_path: &str, gpg_key: Option<&str>, passphrase: Option<&str>) -> Result<()> {
    let img = image::open(input_path)?;
    let (width, height) = img.dimensions();
    let img_rgba = img.to_rgba8();
    
    let mut bits = Vec::new();
    let mut bytes = Vec::new();
    let mut found_marker = false;
    let mut file_size: Option<usize> = None;
    let marker_bytes = FILE_MARKER.as_bytes();
    
    for y in 0..height {
        for x in 0..width {
            let pixel = img_rgba.get_pixel(x, y);
            
            for channel in 0..3 {
                let bit = pixel[channel] & 1;
                bits.push(bit);
                
                if bits.len() == 8 {
                    let mut byte = 0u8;
                    for (i, &bit) in bits.iter().enumerate() {
                        byte |= bit << (7 - i);
                    }
                    bytes.push(byte);
                    bits.clear();
                    
                    if !found_marker && bytes.len() >= marker_bytes.len() {
                        if &bytes[..marker_bytes.len()] == marker_bytes {
                            found_marker = true;
                            bytes.drain(..marker_bytes.len());
                        }
                    }
                    
                    if found_marker && file_size.is_none() && bytes.len() >= 4 {
                        let size_bytes: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
                        file_size = Some(u32::from_be_bytes(size_bytes) as usize);
                        bytes.drain(..4);
                    }
                    
                    if let Some(size) = file_size {
                        if bytes.len() >= size {
                            bytes.truncate(size);
                            
                            let file_data = if let Some(key_path) = gpg_key {
                                crypto::decrypt_data(&bytes, key_path, passphrase)?
                            } else {
                                bytes
                            };
                            
                            let mut file = fs::File::create(output_path)?;
                            file.write_all(&file_data)?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    
    Err(anyhow!("No valid hidden file found or incomplete data"))
}
