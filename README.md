# steganography

Steganography tool for hiding messages in images of multiple formats. Written in Rust with a CLI encoder and decoder using LSB (Least Significant Bit) technique.

## Features

- Encode secret text messages into images
- Encode any number of files and/or whole directories into a single image, preserving file names and directory structure
- Optional GPG public key encryption - only the private key holder can decrypt
- Decode hidden messages and files from images, recreating the original files
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

### Encode files or directories into an image

Hide one or more files inside a carrier image. Binary files are fine; the
original file names are kept so extraction recreates them:

```bash
cargo run -- encode-file -i carrier.png -o output.png -s secret.pdf
cargo run -- encode-file -i carrier.png -o output.png -s secret.pdf -s photo.jpg -s notes.txt
```

Hide a whole directory as it is (nested folders, empty folders and symlinks are
kept). Files and directories can be mixed in one command:

```bash
cargo run -- encode-file -i carrier.png -o output.png -s my_project/
cargo run -- encode-file -i carrier.png -o output.png -s report.pdf -s photos/
```

All secrets are bundled into a gzip-compressed tar archive before embedding, so
you don't need to zip them yourself. Each path is stored under its base name, so
two secrets with the same base name (e.g. `a/f.txt` and `b/f.txt`) are rejected.

With GPG encryption:

```bash
cargo run -- encode-file -i carrier.png -o output.png -s photo.jpg -s docs/ -k public.asc
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

### Decode hidden files

Extract the hidden files into a directory (created if missing; defaults to the
current directory). Original names and directory structure are restored:

```bash
cargo run -- decode-file -i output.png -o extracted/
```

With GPG decryption:

```bash
cargo run -- decode-file -i output.png -o extracted/ -k private.asc -p "passphrase"
```

Note: The private key must match the public key used during encoding. If the
hidden data is encrypted and no key is given, the tool tells you so instead of
failing with a parse error.

Images created by older versions of this tool (single file, no name stored)
are still supported; their content is written to `<output-dir>/hidden.bin`.

### Check image capacity

Find out how many bytes of data an image can store:

```bash
cargo run -- capacity -i image.png
```

### Calculate required size

Find out what size image you need to hide a set of files or directories:

```bash
cargo run -- required -s secret.jpg
cargo run -- required -s report.pdf -s photos/
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
- `-s, --secret <PATH>...` - Secret files and/or directories to hide (repeatable: `-s a -s b` or `-s a b dir/`)
- `-k, --gpg-key <PATH>` - GPG public key file for encryption (optional)

### Decode Command (Text)

- `-i, --input <PATH>` - Path to the image containing the hidden message
- `-k, --gpg-key <PATH>` - GPG private key file for decryption (optional)
- `-p, --passphrase <TEXT>` - GPG key passphrase (optional)

### Decode-File Command

- `-i, --input <PATH>` - Path to the image containing the hidden files
- `-o, --output <DIR>` - Directory to extract the hidden files into (default: `.`)
- `-k, --gpg-key <PATH>` - GPG private key file for decryption (optional)
- `-p, --passphrase <TEXT>` - GPG key passphrase (optional)

### Capacity Command

- `-i, --input <PATH>` - Path to the image to check

### Required Command

- `-s, --secret <PATH>...` - Secret files and/or directories to analyze (repeatable)

## How it works

The tool uses LSB steganography to hide data:

1. **Text Encoding**: The message is converted to binary and embedded into the least significant bits of the image's RGB channels
2. **File Encoding**: The given files and directories are bundled into a gzip-compressed tar archive (preserving names, structure and permissions), which is embedded into the carrier image's LSBs with a marker, a flags byte (records whether the payload is encrypted) and a length prefix
3. **GPG Encryption**: When a GPG public key is provided, the data is encrypted with the recipient's public key before embedding. Only the holder of the corresponding private key can decrypt the hidden data
4. **Decoding**: The least significant bits are extracted and converted back to text, or unpacked from the archive into the output directory with the original file names
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
