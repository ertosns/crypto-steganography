use image::GenericImageView;
use anyhow::{Result, anyhow};
use std::fs;
use std::io::Read;

use crate::crypto;

const END_MARKER: &str = "###END###";
const FILE_MARKER: &str = "###FILE##";

#[derive(Debug)]
pub struct EncodingStats {
    pub capacity: usize,
    pub secret_size: usize,
    pub remaining: usize,
}

impl EncodingStats {
    pub fn usage_percent(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            (self.secret_size as f64 / self.capacity as f64) * 100.0
        }
    }
}

#[derive(Debug)]
pub struct RequiredSize {
    pub secret_size: usize,
    pub min_pixels: usize,
    pub example_width: u32,
    pub example_height: u32,
}

impl RequiredSize {
    pub fn format_bytes(&self, bytes: usize) -> String {
        const KB: usize = 1024;
        const MB: usize = KB * 1024;
        const GB: usize = MB * 1024;
        
        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} bytes", bytes)
        }
    }
    
    pub fn required_image_size(&self) -> usize {
        (self.example_width * self.example_height * 4) as usize
    }
}

pub fn get_capacity(input_path: &str) -> Result<usize> {
    let img = image::open(input_path)?;
    let (width, height) = img.dimensions();
    let total_pixels = (width * height) as usize;
    let total_bits = total_pixels * 3;
    let total_bytes = total_bits / 8;
    let usable_bytes = total_bytes.saturating_sub(END_MARKER.len());
    Ok(usable_bytes)
}

pub fn calculate_required_size(secret_path: &str) -> Result<RequiredSize> {
    let mut file = fs::File::open(secret_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    let marker = FILE_MARKER;
    
    let secret_size = buffer.len() + marker.len() + 4;
    let required_bits = secret_size * 8;
    let min_pixels = (required_bits + 2) / 3;
    
    let side = (min_pixels as f64).sqrt().ceil() as u32;
    
    Ok(RequiredSize {
        secret_size,
        min_pixels,
        example_width: side,
        example_height: side,
    })
}

pub fn encode_text(input_path: &str, output_path: &str, message: &str, gpg_key: Option<&str>) -> Result<EncodingStats> {
    if output_path.to_lowercase().ends_with(".jpg") || output_path.to_lowercase().ends_with(".jpeg") {
        return Err(anyhow!("JPEG format uses lossy compression and will destroy the hidden message. Please use PNG format instead."));
    }
    
    let img = image::open(input_path)?;
    let (width, height) = img.dimensions();
    
    let message_bytes = if let Some(key_path) = gpg_key {
        crypto::encrypt_data(message.as_bytes(), key_path)?
    } else {
        message.as_bytes().to_vec()
    };
    
    let full_message = [&message_bytes[..], END_MARKER.as_bytes()].concat();
    
    let capacity = get_capacity(input_path)?;
    let secret_size = full_message.len();
    
    if secret_size > capacity {
        return Err(anyhow!(
            "Message too long for this image.\n  Required: {} bytes\n  Available: {} bytes\n  Exceeds by: {} bytes",
            secret_size, capacity, secret_size - capacity
        ));
    }
    
    let mut output_img = img.to_rgba8();
    encode_bytes(&mut output_img, &full_message, width, height)?;
    output_img.save(output_path)?;
    
    Ok(EncodingStats {
        capacity,
        secret_size,
        remaining: capacity - secret_size,
    })
}

pub fn encode_file(input_path: &str, output_path: &str, secret_path: &str, gpg_key: Option<&str>) -> Result<EncodingStats> {
    if output_path.to_lowercase().ends_with(".jpg") || output_path.to_lowercase().ends_with(".jpeg") {
        return Err(anyhow!("JPEG format uses lossy compression and will destroy the hidden file. Please use PNG format instead."));
    }
    
    let img = image::open(input_path)?;
    let (width, height) = img.dimensions();
    
    let mut secret_file = fs::File::open(secret_path)?;
    let mut secret_bytes = Vec::new();
    secret_file.read_to_end(&mut secret_bytes)?;
    
    let secret_data = if let Some(key_path) = gpg_key {
        crypto::encrypt_data(&secret_bytes, key_path)?
    } else {
        secret_bytes
    };
    
    let mut data_bytes = FILE_MARKER.as_bytes().to_vec();
    let size_bytes = (secret_data.len() as u32).to_be_bytes();
    data_bytes.extend_from_slice(&size_bytes);
    data_bytes.extend_from_slice(&secret_data);
    
    let capacity = get_capacity(input_path)?;
    let secret_size = data_bytes.len();
    
    if secret_size > capacity {
        return Err(anyhow!(
            "Secret file too large for carrier image.\n  Required: {} bytes\n  Available: {} bytes\n  Exceeds by: {} bytes",
            secret_size, capacity, secret_size - capacity
        ));
    }
    
    let mut output_img = img.to_rgba8();
    encode_bytes(&mut output_img, &data_bytes, width, height)?;
    output_img.save(output_path)?;
    
    Ok(EncodingStats {
        capacity,
        secret_size,
        remaining: capacity - secret_size,
    })
}

fn encode_bytes(output_img: &mut image::RgbaImage, data: &[u8], width: u32, height: u32) -> Result<()> {
    let mut bit_index = 0;
    
    'outer: for y in 0..height {
        for x in 0..width {
            let pixel = output_img.get_pixel_mut(x, y);
            
            for channel in 0..3 {
                if bit_index >= data.len() * 8 {
                    break 'outer;
                }
                
                let byte_index = bit_index / 8;
                let bit_position = 7 - (bit_index % 8);
                let bit = (data[byte_index] >> bit_position) & 1;
                
                pixel[channel] = (pixel[channel] & 0xFE) | bit;
                
                bit_index += 1;
            }
        }
    }
    
    Ok(())
}
