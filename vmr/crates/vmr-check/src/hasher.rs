//! `fileHasher()`: the SHA-256 of a file read in chunks, for `checkFiles`.

use sha2::{Digest, Sha256};

/// A SHA-256 over bytes given in any number of chunks. Any chunking of the
/// same bytes gives the same digest.
#[derive(Clone, Default)]
pub struct FileHasher(Sha256);

impl FileHasher {
    /// A hasher that has seen no bytes.
    pub fn new() -> Self {
        FileHasher(Sha256::new())
    }

    /// Add the next chunk.
    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    /// The digest of every chunk added, as `sha256:` and 64 lower-case hex
    /// digits; the hasher is spent.
    pub fn finish(self) -> String {
        vmr_record::hash::format_hash(&self.0.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_chunking_gives_the_one_shot_digest() {
        let bytes: Vec<u8> = (0..10_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
        let one_shot = vmr_record::hash::format_hash(&vmr_record::hash::sha256(&bytes));
        for size in [1, 2, 63, 64, 65, 4096, 9_999, 10_000, 20_000] {
            let mut h = FileHasher::new();
            for chunk in bytes.chunks(size) {
                h.update(chunk);
            }
            h.update(&[]);
            assert_eq!(h.finish(), one_shot, "chunks of {size}");
        }
        assert_eq!(
            FileHasher::new().finish(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
