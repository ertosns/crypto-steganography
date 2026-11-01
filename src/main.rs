mod archive;
mod encoder;
mod decoder;
mod crypto;

use clap::{Parser, Subcommand};
use anyhow::Result;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "steganography")]
#[command(about = "Hide and extract messages in images using steganography", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Encode a text message into an image")]
    Encode {
        #[arg(short, long, help = "Input image path")]
        input: String,
        
        #[arg(short, long, help = "Output image path")]
        output: String,
        
        #[arg(short, long, help = "Message to hide")]
        message: String,
        
        #[arg(short = 'k', long, help = "GPG public key file for encryption (optional)")]
        gpg_key: Option<String>,
    },
    
    #[command(about = "Decode a text message from an image")]
    Decode {
        #[arg(short, long, help = "Input image path")]
        input: String,
        
        #[arg(short = 'k', long, help = "GPG private key file for decryption (optional)")]
        gpg_key: Option<String>,
        
        #[arg(short = 'p', long, help = "GPG key passphrase (optional)")]
        passphrase: Option<String>,
    },
    
    #[command(about = "Encode one or more files and/or directories into an image")]
    EncodeFile {
        #[arg(short, long, help = "Carrier image path")]
        input: String,
        
        #[arg(short, long, help = "Output image path (PNG)")]
        output: String,
        
        // This subcommand has no positional arguments, so `num_args = 1..` is
        // safe: `-s a b dir/` and `-s a -s b -s dir/` both work. If a positional
        // is ever added here, drop `num_args` and rely on repeated `-s`.
        #[arg(short, long, required = true, num_args = 1.., value_name = "PATH",
              help = "Secret files and/or directories to hide (repeatable); names are preserved")]
        secret: Vec<PathBuf>,
        
        #[arg(short = 'k', long, help = "GPG public key file for encryption (optional)")]
        gpg_key: Option<String>,
    },
    
    #[command(about = "Extract hidden files from an image into a directory")]
    DecodeFile {
        #[arg(short, long, help = "Input image path")]
        input: String,
        
        #[arg(short, long, default_value = ".", help = "Directory to extract hidden files into (created if missing)")]
        output: PathBuf,
        
        #[arg(short = 'k', long, help = "GPG private key file for decryption (optional)")]
        gpg_key: Option<String>,
        
        #[arg(short = 'p', long, help = "GPG key passphrase (optional)")]
        passphrase: Option<String>,
    },
    
    #[command(about = "Check how many bytes an image can store")]
    Capacity {
        #[arg(short, long, help = "Input image path")]
        input: String,
    },
    
    #[command(about = "Calculate minimum image size needed to hide the given secrets")]
    Required {
        #[arg(short, long, required = true, num_args = 1.., value_name = "PATH",
              help = "Secret files and/or directories to analyze (repeatable)")]
        secret: Vec<PathBuf>,
    },
}

fn print_stats(stats: &encoder::EncodingStats) {
    println!("\nStatistics:");
    println!("  Available capacity: {} bytes", stats.capacity);
    println!("  Secret size: {} bytes", stats.secret_size);
    println!("  Remaining space: {} bytes", stats.remaining);
    println!("  Usage: {:.2}%", stats.usage_percent());
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Encode { input, output, message, gpg_key } => {
            let stats = encoder::encode_text(&input, &output, &message, gpg_key.as_deref())?;
            println!("Message successfully encoded into {}", output);
            if gpg_key.is_some() {
                println!("Message was encrypted with GPG");
            }
            print_stats(&stats);
        }
        Commands::Decode { input, gpg_key, passphrase } => {
            let message = decoder::decode_text(&input, gpg_key.as_deref(), passphrase.as_deref())?;
            println!("Decoded message: {}", message);
        }
        Commands::EncodeFile { input, output, secret, gpg_key } => {
            let stats = encoder::encode_files(&input, &output, &secret, gpg_key.as_deref())?;
            println!("{} path(s) successfully encoded into {}", secret.len(), output);
            if gpg_key.is_some() {
                println!("Files were encrypted with GPG");
            }
            print_stats(&stats);
        }
        Commands::DecodeFile { input, output, gpg_key, passphrase } => {
            let entries = decoder::decode_file(&input, &output, gpg_key.as_deref(), passphrase.as_deref())?;
            println!("Extracted {} entries into {}:", entries.len(), output.display());
            for entry in &entries {
                println!("  {}", output.join(entry).display());
            }
        }
        Commands::Capacity { input } => {
            let capacity = encoder::get_capacity(&input)?;
            println!("Image capacity: {} bytes", capacity);
            println!("Approximately {} characters of text", capacity);
        }
        Commands::Required { secret } => {
            let required = encoder::calculate_required_size(&secret)?;
            println!("Secret analysis ({} path(s), bundled as tar.gz):", secret.len());
            println!("  Secret size: {}", required.format_bytes(required.secret_size));
            println!();
            println!("Minimum carrier image requirements:");
            println!("  Minimum pixels: {} pixels", required.min_pixels);
            println!("  Example dimensions: {}x{} pixels", required.example_width, required.example_height);
            println!("  Approximate file size: {} (PNG format)", required.format_bytes(required.required_image_size()));
        }
    }
    
    Ok(())
}
