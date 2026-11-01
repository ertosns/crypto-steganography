use image::{GenericImageView, RgbaImage};
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};

use crate::archive;
use crate::crypto;
use crate::encoder::{END_MARKER, FILE_MARKER, TAR_MARKER, FLAG_ENCRYPTED};

/// Name given to payloads hidden by the legacy single-file framing, which
/// stored no filename.
pub const LEGACY_FILE_NAME: &str = "hidden.bin";

/// Sequential reader over the RGB least-significant bits of an image, in the
/// same order `encoder::encode_bytes` writes them (row-major, R then G then B,
/// MSB-first within each byte).
struct LsbReader<'a> {
    img: &'a RgbaImage,
    width: u64,
    total_bits: u64,
    bit_pos: u64,
}

impl<'a> LsbReader<'a> {
    fn new(img: &'a RgbaImage) -> Self {
        let (w, h) = img.dimensions();
        Self {
            img,
            width: w as u64,
            total_bits: w as u64 * h as u64 * 3,
            bit_pos: 0,
        }
    }
    
    fn remaining_bytes(&self) -> u64 {
        (self.total_bits - self.bit_pos) / 8
    }
    
    fn read_bit(&mut self) -> Option<u8> {
        if self.bit_pos >= self.total_bits {
            return None;
        }
        let pixel = self.bit_pos / 3;
        let channel = (self.bit_pos % 3) as usize;
        let x = (pixel % self.width) as u32;
        let y = (pixel / self.width) as u32;
        self.bit_pos += 1;
        Some(self.img.get_pixel(x, y)[channel] & 1)
    }
    
    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let mut byte = 0u8;
            for _ in 0..8 {
                let bit = self
                    .read_bit()
                    .ok_or_else(|| anyhow!("No valid hidden file found or incomplete data"))?;
                byte = (byte << 1) | bit;
            }
            out.push(byte);
        }
        Ok(out)
    }
    
    fn read_u32_be(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    
    /// Reads a `u32 BE length || payload` sequence, rejecting lengths the image
    /// cannot hold so that random images fail fast with a clear error.
    fn read_length_prefixed(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32_be()? as u64;
        if len > self.remaining_bytes() {
            return Err(anyhow!(
                "Declared payload length {} exceeds image capacity; image does not contain valid hidden data",
                len
            ));
        }
        self.read_bytes(len as usize)
    }
}

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

/// Extract the hidden files into `output_dir` (created if missing) and return
/// the extracted paths relative to it.
///
/// Images produced by the archive framing are unpacked with their original
/// names and directory structure. Images produced by the legacy single-file
/// framing are written to `<output_dir>/hidden.bin`.
pub fn decode_file(input_path: &str, output_dir: &Path, gpg_key: Option<&str>, passphrase: Option<&str>) -> Result<Vec<PathBuf>> {
    let img = image::open(input_path)?.to_rgba8();
    let mut reader = LsbReader::new(&img);
    let marker = reader.read_bytes(TAR_MARKER.len())?;
    
    if marker == TAR_MARKER.as_bytes() {
        let flags = reader.read_bytes(1)?[0];
        if flags & !FLAG_ENCRYPTED != 0 {
            return Err(anyhow!(
                "Unsupported archive flags 0x{:02x}; was this image created by a newer version?",
                flags
            ));
        }
        
        let payload = reader.read_length_prefixed()?;
        let archive_bytes = if flags & FLAG_ENCRYPTED != 0 {
            let key_path = gpg_key.ok_or_else(|| {
                anyhow!("Hidden data is GPG-encrypted; provide the private key with -k/--gpg-key")
            })?;
            crypto::decrypt_data(&payload, key_path, passphrase)?
        } else {
            payload
        };
        
        archive::unpack(&archive_bytes, output_dir)
    } else if marker == FILE_MARKER.as_bytes() {
        let payload = reader.read_length_prefixed()?;
        let file_data = match gpg_key {
            Some(key_path) => crypto::decrypt_data(&payload, key_path, passphrase)?,
            None => payload,
        };
        
        fs::create_dir_all(output_dir)?;
        fs::write(output_dir.join(LEGACY_FILE_NAME), file_data)?;
        Ok(vec![PathBuf::from(LEGACY_FILE_NAME)])
    } else {
        Err(anyhow!("No valid hidden file found in image"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder;
    use image::Rgba;
    use tempfile::tempdir;

    fn carrier(dir: &Path, side: u32) -> String {
        let img = RgbaImage::from_fn(side, side, |x, y| {
            Rgba([x as u8, y as u8, (x ^ y) as u8, 255])
        });
        let path = dir.join("carrier.png");
        img.save(&path).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn encode_decode_files_and_dir_round_trip() {
        let tmp = tempdir().unwrap();
        let carrier_path = carrier(tmp.path(), 256);
        let out = tmp.path().join("out.png");

        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("photos/nested")).unwrap();
        let binary: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        fs::write(src.join("notes.txt"), "secret notes").unwrap();
        fs::write(src.join("blob.bin"), &binary).unwrap();
        fs::write(src.join("photos/nested/pic.raw"), &binary[..100]).unwrap();

        let paths = vec![src.join("notes.txt"), src.join("blob.bin"), src.join("photos")];
        let stats = encoder::encode_files(&carrier_path, out.to_str().unwrap(), &paths, None).unwrap();
        assert!(stats.secret_size > 0 && stats.secret_size <= stats.capacity);

        let extract = tmp.path().join("extract");
        let names = decode_file(out.to_str().unwrap(), &extract, None, None).unwrap();

        assert_eq!(fs::read(extract.join("notes.txt")).unwrap(), b"secret notes");
        assert_eq!(fs::read(extract.join("blob.bin")).unwrap(), binary);
        assert_eq!(fs::read(extract.join("photos/nested/pic.raw")).unwrap(), &binary[..100]);
        for expected in ["notes.txt", "blob.bin", "photos/nested/pic.raw"] {
            assert!(names.iter().any(|n| n == Path::new(expected)), "missing {expected}");
        }
    }

    #[test]
    fn legacy_file_marker_still_decodes() {
        let tmp = tempdir().unwrap();
        let carrier_path = carrier(tmp.path(), 64);
        let out = tmp.path().join("out.png");

        let payload = b"hello legacy";
        let mut framed = FILE_MARKER.as_bytes().to_vec();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        encoder::embed(&carrier_path, out.to_str().unwrap(), &framed).unwrap();

        let extract = tmp.path().join("extract");
        let names = decode_file(out.to_str().unwrap(), &extract, None, None).unwrap();
        assert_eq!(names, vec![PathBuf::from(LEGACY_FILE_NAME)]);
        assert_eq!(fs::read(extract.join(LEGACY_FILE_NAME)).unwrap(), payload);
    }

    #[test]
    fn encrypted_flag_without_key_errors() {
        let tmp = tempdir().unwrap();
        let carrier_path = carrier(tmp.path(), 64);
        let out = tmp.path().join("out.png");

        let payload = [1u8, 2, 3, 4];
        let mut framed = TAR_MARKER.as_bytes().to_vec();
        framed.push(FLAG_ENCRYPTED);
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(&payload);
        encoder::embed(&carrier_path, out.to_str().unwrap(), &framed).unwrap();

        let err = decode_file(out.to_str().unwrap(), &tmp.path().join("x"), None, None).unwrap_err();
        assert!(err.to_string().contains("--gpg-key"), "{err}");
    }

    #[test]
    fn garbage_image_errors() {
        let tmp = tempdir().unwrap();
        let carrier_path = carrier(tmp.path(), 64);
        assert!(decode_file(&carrier_path, &tmp.path().join("x"), None, None).is_err());
    }

    #[test]
    fn too_large_errors() {
        let tmp = tempdir().unwrap();
        let carrier_path = carrier(tmp.path(), 4);
        let out = tmp.path().join("out.png");
        let big = tmp.path().join("big.bin");
        let data: Vec<u8> = (0..1024u32).map(|i| (i * 7919 % 251) as u8).collect();
        fs::write(&big, data).unwrap();
        assert!(encoder::encode_files(&carrier_path, out.to_str().unwrap(), &[big], None).is_err());
    }
}
