# steganography

Steganography tool for hiding messages in images of multiple formats. Written in Rust with a CLI encoder and decoder using LSB (Least Significant Bit) technique.

## Features

- Encode secret text messages into images
- Encode any file (images, documents, archives, etc.) into images
- Optional GPG public key encryption - only the private key holder can decrypt
- Decode hidden messages and files from images
- Check storage capacity of any image
- Calculate minimum image size needed for a secret
- Detailed statistics on space usage and availability
- Support for multiple image formats (PNG, JPG, BMP, GIF, etc.)
- Simple command-line interface
- Preserves image visual quality

## Installation

Make sure you have Rust installed. Then clone and build:

```bash
git clone <repository-url>
cd steganography
cargo build --release
```

## Usage

### Encode a text message

Hide a message in an image (must use PNG format for output):

```bash
cargo run -- encode -i input.png -o output.png -m "Your secret message"
```

With GPG encryption:

```bash
cargo run -- encode -i input.png -o output.png -m "Your secret message" -k public.asc
```

You can use any format for input, but output must be PNG:

```bash
cargo run -- encode -i photo.jpg -o encoded.png -m "Your secret message"
```

### Encode a file into an image

Hide any file inside a carrier image:

```bash
cargo run -- encode-file -i carrier.png -o output.png -s secret.pdf
cargo run -- encode-file -i carrier.png -o output.png -s document.zip
```

With GPG encryption:

```bash
cargo run -- encode-file -i carrier.png -o output.png -s photo.jpg -k public.asc
```

### Decode a text message

Extract a hidden text message from an image:

```bash
cargo run -- decode -i output.png
```

With GPG encryption:

```bash
cargo run -- decode -i output.png -k private.asc -p "passphrase"
```

Note: You must provide the private key corresponding to the public key used during encoding.

### Decode a hidden file

Extract a hidden file from a carrier image:

```bash
cargo run -- decode-file -i output.png -o extracted.pdf
```

With GPG decryption:

```bash
cargo run -- decode-file -i output.png -o extracted.pdf -k private.asc -p "passphrase"
```

Note: The private key must match the public key used during encoding.

### Check image capacity

Find out how many bytes of data an image can store:

```bash
cargo run -- capacity -i image.png
```

### Calculate required size

Find out what size image you need to hide a specific file:

```bash
cargo run -- required -s secret.jpg
```

## Options

### Encode Command (Text)

- `-i, --input <PATH>` - Path to the carrier image
- `-o, --output <PATH>` - Path to save the output image (must be PNG)
- `-m, --message <TEXT>` - The text message to hide
- `-k, --gpg-key <PATH>` - GPG public key file for encryption (optional)

### Encode-File Command

- `-i, --input <PATH>` - Path to the carrier image
- `-o, --output <PATH>` - Path to save the output image (must be PNG)
- `-s, --secret <PATH>` - Path to the secret file to hide
- `-k, --gpg-key <PATH>` - GPG public key file for encryption (optional)

### Decode Command (Text)

- `-i, --input <PATH>` - Path to the image containing the hidden message
- `-k, --gpg-key <PATH>` - GPG private key file for decryption (optional)
- `-p, --passphrase <TEXT>` - GPG key passphrase (optional)

### Decode-File Command

- `-i, --input <PATH>` - Path to the image containing the hidden file
- `-o, --output <PATH>` - Path to save the extracted secret file
- `-k, --gpg-key <PATH>` - GPG private key file for decryption (optional)
- `-p, --passphrase <TEXT>` - GPG key passphrase (optional)

### Capacity Command

- `-i, --input <PATH>` - Path to the image to check

### Required Command

- `-s, --secret <PATH>` - Path to the secret file to analyze

## How it works

The tool uses LSB steganography to hide data:

1. **Text Encoding**: The message is converted to binary and embedded into the least significant bits of the image's RGB channels
2. **File Encoding**: Any file is read as binary data and embedded into the carrier image's LSBs with a length prefix
3. **GPG Encryption**: When a GPG public key is provided, the data is encrypted with the recipient's public key before embedding. Only the holder of the corresponding private key can decrypt the hidden data
4. **Decoding**: The least significant bits are extracted and converted back to text or binary file data
5. **GPG Decryption**: If the data was encrypted, the private key and passphrase must be provided to decrypt it
6. **Validation**: Before encoding, the tool validates that the carrier image has enough capacity
7. **Statistics**: After encoding, detailed statistics show capacity, usage, and remaining space
8. Markers and length prefixes ensure data can be reliably extracted

## Requirements

- Rust 1.70 or higher
- Cargo

## Limitations

- Message size is limited by image dimensions (larger images can store longer messages)
- **Output must be PNG format** - JPEG and other lossy formats will destroy the hidden message
- Input can be any supported format, but will be converted to PNG for encoding
- For decoding, only use images that were saved as PNG after encoding
