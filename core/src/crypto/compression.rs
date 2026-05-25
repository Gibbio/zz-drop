//! zstd compression / decompression for the `x` modifier.
//!
//! Only one algorithm is supported: zstd via the `zstd` crate
//! (libzstd binding). Default compression level is `3`, the
//! upstream zstd default — balanced ratio/speed and the value
//! the v1 grammar locks in.
//!
//! Decompression is auto-detect: callers run [`is_zstd_magic`] on
//! the first four bytes of a remote blob and dispatch to
//! [`decompress`] when the marker matches. Plaintext blobs flow
//! through unchanged.
//!
//! Files smaller than [`COMPRESS_SKIP_THRESHOLD_BYTES`] should
//! skip the compress step on the upload side: zstd's frame
//! header (~17 bytes) makes a tiny payload bigger, not smaller.

use std::io;

/// zstd v1 magic header at offset 0: `28 B5 2F FD`. Stable
/// across the format; clients use it to dispatch download
/// pipelines without metadata exchange.
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// POSIX `ustar\0` magic at offset 257 inside an archive's
/// first 512-byte header block.
pub const TAR_USTAR_MAGIC: &[u8; 6] = b"ustar\0";

/// GNU tar magic — same offset 257, but the trailing NUL is a
/// space and the version field is `' '` `\0`. Modern GNU tar
/// and the Rust `tar` crate's default header write this variant.
/// The bytes at 257..263 are `u s t a r SPACE` for GNU vs.
/// `u s t a r NUL` for strict POSIX.
pub const TAR_USTAR_MAGIC_GNU: &[u8; 6] = b"ustar ";

/// File-size cutoff below which the `x` modifier skips zstd on
/// upload. Matches the v1 design freeze (4 KiB).
pub const COMPRESS_SKIP_THRESHOLD_BYTES: usize = 4 * 1024;

/// Default zstd compression level for the `x` modifier in v1.
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// Returns `true` when `bytes` starts with the zstd v1 magic
/// number (`28 B5 2F FD`). Plaintext payloads return `false`.
pub fn is_zstd_magic(bytes: &[u8]) -> bool {
    bytes.len() >= ZSTD_MAGIC.len() && bytes[..ZSTD_MAGIC.len()] == ZSTD_MAGIC
}

/// Returns `true` when `bytes` looks like the first 512 bytes of
/// a tar archive. Accepts both POSIX (`ustar\0`) and GNU
/// (`ustar `) magic at offset 257 — the Rust `tar` crate's
/// default header is GNU, so a strict POSIX-only check would
/// silently skip extraction of bundles produced by our own
/// upload path. Used to chain "decompress → extract" inside
/// `zz dx <archive>.tar.zst`.
pub fn is_tar_ustar(bytes: &[u8]) -> bool {
    const OFFSET: usize = 257;
    const LEN: usize = 6;
    if bytes.len() < OFFSET + LEN {
        return false;
    }
    let window = &bytes[OFFSET..OFFSET + LEN];
    window == TAR_USTAR_MAGIC || window == TAR_USTAR_MAGIC_GNU
}

/// Compress `plaintext` into a `Vec<u8>` using zstd at the
/// given level. Level `3` is the project default; the wider
/// range supported by v1 callers is `1..=9`.
pub fn compress(plaintext: &[u8], level: i32) -> io::Result<Vec<u8>> {
    zstd::stream::encode_all(plaintext, level)
}

/// Decompress a zstd-encoded blob. Returns the decoded bytes.
/// Errors propagate from the underlying decoder (truncated
/// frame, unsupported version, etc.).
///
/// ⚠️ Unbounded output: only call this on input you produced. For
/// remote/attacker-controlled blobs use [`decompress_capped`], which
/// bounds the decompressed size to defend against a zstd bomb.
pub fn decompress(ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    zstd::stream::decode_all(ciphertext)
}

/// Default ceiling on decompressed output for remote blobs. A
/// downloaded blob is itself capped at ~10 MiB by the HTTP client, but
/// zstd's expansion ratio is unbounded (>1000:1 trivially), so without
/// an output cap a small malicious `.zst` could inflate to many GB and
/// exhaust memory. 512 MiB is ~50× the download cap — generous for any
/// legitimate file this tool moves, while blocking the bomb. See
/// security audit D6.
pub const MAX_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Decompress a zstd blob, refusing output larger than `max_bytes`.
/// Streams through the decoder so the bomb is stopped *before* the
/// oversized buffer is fully materialised, then fails with
/// `InvalidData` rather than allocating without bound.
pub fn decompress_capped(ciphertext: &[u8], max_bytes: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;

    let mut decoder = zstd::stream::read::Decoder::new(ciphertext)?;
    let mut out = Vec::new();
    // Read at most max_bytes+1 so an output of exactly the limit is
    // accepted while anything larger is detected and rejected.
    decoder
        .by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut out)?;
    if out.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decompressed output exceeds {max_bytes}-byte limit"),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_match_only_on_full_prefix() {
        assert!(is_zstd_magic(&[0x28, 0xB5, 0x2F, 0xFD]));
        assert!(is_zstd_magic(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]));
        // Wrong byte at any position = no match.
        assert!(!is_zstd_magic(&[0x28, 0xB5, 0x2F, 0xFE]));
        assert!(!is_zstd_magic(&[0x29, 0xB5, 0x2F, 0xFD]));
        // Too short = no match (rejects partial reads).
        assert!(!is_zstd_magic(&[0x28, 0xB5, 0x2F]));
        assert!(!is_zstd_magic(&[]));
    }

    #[test]
    fn tar_ustar_detected_at_offset_257() {
        // Build the smallest plausible buffer: 257 zero bytes,
        // the magic, padding to a 512-block boundary.
        let mut buf = vec![0u8; 257];
        buf.extend_from_slice(TAR_USTAR_MAGIC);
        buf.resize(512, 0);
        assert!(is_tar_ustar(&buf));

        // Magic at the wrong offset = no detection.
        let mut shifted = vec![0u8; 100];
        shifted.extend_from_slice(TAR_USTAR_MAGIC);
        shifted.resize(512, 0);
        assert!(!is_tar_ustar(&shifted));

        // Truncated buffer: even if the magic appears in the
        // bytes we hold, an undersized header doesn't qualify.
        assert!(!is_tar_ustar(&buf[..200]));
    }

    #[test]
    fn tar_gnu_magic_also_detected() {
        // Regression guard: the Rust `tar` crate's default
        // writer emits the GNU variant (`ustar `, with a space
        // instead of NUL at byte 5). A strict POSIX-only check
        // would silently skip extraction of bundles produced by
        // our own `zz sax` / `zz sarx` path.
        let mut buf = vec![0u8; 257];
        buf.extend_from_slice(TAR_USTAR_MAGIC_GNU);
        buf.resize(512, 0);
        assert!(is_tar_ustar(&buf), "GNU `ustar ` magic must be accepted");

        // Anything else at that slot is not a tar.
        let mut other = vec![0u8; 257];
        other.extend_from_slice(b"abcdef");
        other.resize(512, 0);
        assert!(!is_tar_ustar(&other));
    }

    #[test]
    fn round_trip_preserves_bytes_at_default_level() {
        let plaintext = b"hello, zz-drop \xE2\x9C\x93 \x00 mixed bytes \xFF";
        let compressed = compress(plaintext, DEFAULT_COMPRESSION_LEVEL).unwrap();
        // The output must start with the zstd magic.
        assert!(is_zstd_magic(&compressed));
        // And decompress to the exact same bytes.
        let decoded = decompress(&compressed).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn round_trip_works_across_supported_levels() {
        let plaintext = b"the quick brown fox ".repeat(64);
        for level in [1, 3, 9] {
            let compressed = compress(&plaintext, level).unwrap();
            let decoded = decompress(&compressed).unwrap();
            assert_eq!(decoded, plaintext, "level {level} must round-trip");
        }
    }

    #[test]
    fn tiny_payload_grows_after_compress_so_skip_makes_sense() {
        // The skip threshold exists exactly because zstd's frame
        // header dominates on tiny inputs. This locks the
        // assumption: a single byte goes from 1 to ~14 bytes.
        let plaintext = b"x";
        let compressed = compress(plaintext, DEFAULT_COMPRESSION_LEVEL).unwrap();
        assert!(
            compressed.len() > plaintext.len(),
            "tiny payload must grow when zstd-encoded ({} bytes after compress)",
            compressed.len()
        );
    }

    #[test]
    fn highly_compressible_input_shrinks() {
        // 64 KiB of zeros is ~99 % compressible; this is the
        // sanity case for the algorithm.
        let plaintext = vec![0u8; 64 * 1024];
        let compressed = compress(&plaintext, DEFAULT_COMPRESSION_LEVEL).unwrap();
        assert!(
            compressed.len() < plaintext.len() / 10,
            "expected zeros to compress > 10×, got {} → {}",
            plaintext.len(),
            compressed.len(),
        );
        let decoded = decompress(&compressed).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn decompress_capped_rejects_bomb_but_allows_within_limit() {
        // 5 MiB of zeros compresses to a few KB — a miniature bomb.
        let payload = vec![0u8; 5 * 1024 * 1024];
        let compressed = compress(&payload, DEFAULT_COMPRESSION_LEVEL).unwrap();
        assert!(
            compressed.len() < 64 * 1024,
            "zeros should compress to a tiny blob ({} bytes)",
            compressed.len()
        );

        // Cap below the true output → rejected before full allocation.
        let err = decompress_capped(&compressed, 1024 * 1024); // 1 MiB < 5 MiB
        assert!(err.is_err(), "5 MiB output must exceed a 1 MiB cap");

        // Cap above the true output → succeeds and round-trips exactly.
        let ok = decompress_capped(&compressed, 16 * 1024 * 1024).unwrap();
        assert_eq!(ok, payload);
    }

    #[test]
    fn decompress_capped_accepts_output_exactly_at_limit() {
        let payload = b"abc".repeat(4096); // 12_288 bytes
        let compressed = compress(&payload, DEFAULT_COMPRESSION_LEVEL).unwrap();
        let ok = decompress_capped(&compressed, payload.len() as u64).unwrap();
        assert_eq!(ok, payload);
    }

    #[test]
    fn decompress_rejects_truncated_frame() {
        let plaintext = b"ABCD".repeat(64);
        let compressed = compress(&plaintext, DEFAULT_COMPRESSION_LEVEL).unwrap();
        // Lop off the last byte; the AEAD-equivalent check for
        // zstd is the trailing checksum / frame-end marker.
        let truncated = &compressed[..compressed.len() - 1];
        assert!(decompress(truncated).is_err());
    }

    #[test]
    fn skip_threshold_is_4_kib() {
        // The constant is part of the v1 public-facing contract
        // (mentioned in the README and the file-encryption
        // spec). Lock it so a future refactor doesn't drift.
        assert_eq!(COMPRESS_SKIP_THRESHOLD_BYTES, 4 * 1024);
    }

    #[test]
    fn default_level_is_three() {
        assert_eq!(DEFAULT_COMPRESSION_LEVEL, 3);
    }
}
