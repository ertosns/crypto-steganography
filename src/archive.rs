//! Bundles files and directories into a gzip-compressed tar archive so that
//! several secrets (with their original names and directory structure) can be
//! hidden in a single carrier image.

use anyhow::{anyhow, bail, Context, Result};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};

/// Top-level name an input path gets inside the archive.
///
/// `.`, `..` and `/` have no `file_name`; canonicalize to recover a real name.
fn entry_name(path: &Path) -> Result<OsString> {
    if let Some(name) = path.file_name() {
        return Ok(name.to_os_string());
    }
    path.canonicalize()?
        .file_name()
        .map(|n| n.to_os_string())
        .ok_or_else(|| anyhow!("Cannot derive an archive name for {}", path.display()))
}

/// Pack files and directories into a gzip-compressed tar archive.
///
/// Each path is stored under its base name; directories are stored recursively
/// as-is (including empty subdirectories and symlinks).
pub fn pack(paths: &[PathBuf]) -> Result<Vec<u8>> {
    if paths.is_empty() {
        bail!("At least one secret path is required");
    }

    let mut builder = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    // Store symlinks as symlinks: keeps the directory "as it is" and avoids
    // infinite loops on cyclic links.
    builder.follow_symlinks(false);

    let mut seen: HashSet<OsString> = HashSet::new();
    for path in paths {
        let meta = fs::metadata(path)
            .with_context(|| format!("Cannot read secret path {}", path.display()))?;
        let name = entry_name(path)?;
        if !seen.insert(name.clone()) {
            bail!(
                "Duplicate top-level name '{}': secret paths must have distinct base names",
                Path::new(&name).display()
            );
        }
        if meta.is_dir() {
            builder
                .append_dir_all(&name, path)
                .with_context(|| format!("Failed to add directory {}", path.display()))?;
        } else if meta.is_file() {
            builder
                .append_path_with_name(path, &name)
                .with_context(|| format!("Failed to add file {}", path.display()))?;
        } else {
            bail!("{} is neither a regular file nor a directory", path.display());
        }
    }

    let gz = builder.into_inner()?; // writes the tar trailer, returns the GzEncoder
    Ok(gz.finish()?)
}

/// Unpack a gzip-compressed tar archive into `dest` (created if missing).
///
/// Returns the entry paths relative to `dest`. The `tar` crate strips absolute
/// and `..` components and refuses to write through symlinks, so a hostile
/// archive cannot escape `dest`.
pub fn unpack(bytes: &[u8], dest: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(dest)
        .with_context(|| format!("Cannot create output directory {}", dest.display()))?;

    let mut names = Vec::new();
    let mut listing = Archive::new(GzDecoder::new(bytes));
    for entry in listing
        .entries()
        .context("Hidden data is not a valid archive")?
    {
        names.push(entry?.path()?.into_owned());
    }

    let mut archive = Archive::new(GzDecoder::new(bytes));
    archive
        .unpack(dest)
        .context("Failed to extract hidden archive")?;
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_files_and_nested_dir() {
        let src = tempdir().unwrap();
        let binary: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
        fs::write(src.path().join("a.txt"), "hello").unwrap();
        fs::write(src.path().join("b.bin"), &binary).unwrap();
        fs::create_dir_all(src.path().join("dir/sub")).unwrap();
        fs::create_dir_all(src.path().join("dir/empty")).unwrap();
        fs::write(src.path().join("dir/sub/c.txt"), "nested").unwrap();

        let bytes = pack(&[
            src.path().join("a.txt"),
            src.path().join("b.bin"),
            src.path().join("dir"),
        ])
        .unwrap();

        let dst = tempdir().unwrap();
        let names = unpack(&bytes, dst.path()).unwrap();

        assert_eq!(fs::read(dst.path().join("a.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(dst.path().join("b.bin")).unwrap(), binary);
        assert_eq!(fs::read(dst.path().join("dir/sub/c.txt")).unwrap(), b"nested");
        assert!(dst.path().join("dir/empty").is_dir());
        for expected in ["a.txt", "b.bin", "dir/sub/c.txt"] {
            assert!(names.iter().any(|n| n == Path::new(expected)), "missing {expected}");
        }
    }

    #[test]
    fn pack_rejects_empty() {
        assert!(pack(&[]).is_err());
    }

    #[test]
    fn pack_rejects_missing_path() {
        let src = tempdir().unwrap();
        assert!(pack(&[src.path().join("nope")]).is_err());
    }

    #[test]
    fn pack_rejects_duplicate_names() {
        let src = tempdir().unwrap();
        fs::create_dir_all(src.path().join("x")).unwrap();
        fs::create_dir_all(src.path().join("y")).unwrap();
        fs::write(src.path().join("x/f.txt"), "1").unwrap();
        fs::write(src.path().join("y/f.txt"), "2").unwrap();
        let err = pack(&[src.path().join("x/f.txt"), src.path().join("y/f.txt")]).unwrap_err();
        assert!(err.to_string().contains("Duplicate"));
    }

    #[test]
    fn entry_name_of_dot_is_cwd_basename() {
        let name = entry_name(Path::new(".")).unwrap();
        let expected = std::env::current_dir().unwrap().file_name().unwrap().to_os_string();
        assert_eq!(name, expected);
    }
}
