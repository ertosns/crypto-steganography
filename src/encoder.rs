use image::GenericImageView;
use anyhow::{Result, anyhow};
use std::path::PathBuf;

use crate::archive;
use crate::crypto;

/// Text framing: `payload || END_MARKER`.
pub(crate) const END_MARKER: &str = "###END###";
/// Legacy single-file framing: `FILE_MARKER || u32 BE len || payload` (no filename).
pub(crate) const FILE_MARKER: &str = "###FILE##";
/// Archive framing: `TAR_MARKER || flags u8 || u32 BE len || gzip'd tar payload`.
pub(crate) const TAR_MARKER: &str = "###TAR###";
/// Flag bit: the archive payload is PGP-encrypted.
pub(crate) const FLAG_ENCRYPTED: u8 = 0b0000_0001;
/// Marker + flags + length.
pub(crate) const TAR_HEADER_LEN: usize = TAR_MARKER.len() + 1 + 4;

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

/// Usable payload bytes for an image of the given dimensions (3 LSBs per pixel).
pub(crate) fn capacity_for_dims(width: u32, height: u32) -> usize {
    let total_bits = width as usize * height as usize * 3;
    (total_bits / 8).saturating_sub(END_MARKER.len())
}

pub fn get_capacity(input_path: &str) -> Result<usize> {
    let img = image::open(input_path)?;
    let (width, height) = img.dimensions();
    Ok(capacity_for_dims(width, height))
}

/// Minimum carrier size for hiding the given files/directories (unencrypted estimate).
pub fn calculate_required_size(secrets: &[PathBuf]) -> Result<RequiredSize> {
    let archive_bytes = archive::pack(secrets)?;
    
    let secret_size = archive_bytes.len() + TAR_HEADER_LEN;
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
    let message_bytes = if let Some(key_path) = gpg_key {
        crypto::encrypt_data(message.as_bytes(), key_path)?
    } else {
        message.as_bytes().to_vec()
    };
    
    let framed = [&message_bytes[..], END_MARKER.as_bytes()].concat();
    embed(input_path, output_path, &framed)
}

/// Hide one or more files and/or directories in the carrier image, preserving
/// their names and directory structure.
pub fn encode_files(input_path: &str, output_path: &str, secrets: &[PathBuf], gpg_key: Option<&str>) -> Result<EncodingStats> {
    let archive_bytes = archive::pack(secrets)?;
    
    let (payload, flags) = match gpg_key {
        Some(key_path) => (crypto::encrypt_data(&archive_bytes, key_path)?, FLAG_ENCRYPTED),
        None => (archive_bytes, 0),
    };
    
    embed(input_path, output_path, &frame_archive(&payload, flags)?)
}

fn frame_archive(payload: &[u8], flags: u8) -> Result<Vec<u8>> {
    let len = u32::try_from(payload.len())
        .map_err(|_| anyhow!("Payload exceeds the 4 GiB framing limit"))?;
    let mut framed = Vec::with_capacity(TAR_HEADER_LEN + payload.len());
    framed.extend_from_slice(TAR_MARKER.as_bytes());
    framed.push(flags);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Write an already-framed byte sequence into the carrier's LSBs and save it.
pub(crate) fn embed(input_path: &str, output_path: &str, framed: &[u8]) -> Result<EncodingStats> {
    let lower = output_path.to_lowercase();
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        return Err(anyhow!("JPEG format uses lossy compression and will destroy the hidden data. Please use PNG format instead."));
    }
    
    let img = image::open(input_path)?;
    let (width, height) = img.dimensions();
    
    let capacity = capacity_for_dims(width, height);
    let secret_size = framed.len();
    
    if secret_size > capacity {
        return Err(anyhow!(
            "Secret too large for carrier image.\n  Required: {} bytes\n  Available: {} bytes\n  Exceeds by: {} bytes",
            secret_size, capacity, secret_size - capacity
        ));
    }
    
    let mut output_img = img.to_rgba8();
    encode_bytes(&mut output_img, framed, width, height)?;
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
