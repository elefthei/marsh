//! Short, stable identifiers: each job snapshot's name.

use sha1::{Digest, Sha1};

/// Number of hex characters kept from a digest.
const ID_LENGTH: usize = 8;

/// The first [`ID_LENGTH`] hex characters of `sha1(input)`.
///
/// Short by design: these name directories a user types. Collisions are possible in principle and
/// harmless in practice — a job id is redrawn from a monotonic counter, so an existing directory is
/// proof of a live id, never of a lost one.
pub(crate) fn short_id(input: &str) -> String {
    let digest = Sha1::digest(input.as_bytes());
    // Two hex characters per byte, so encoding the first `ID_LENGTH / 2` bytes *is* the
    // `ID_LENGTH`-character prefix — without rendering the other 32 characters to throw away.
    hex::encode(&digest[..ID_LENGTH / 2])
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The id names a directory the console shows in its prompt, so its derivation is pinned: a
    /// job id is drawn from the seed, the job's name, a monotonic counter and the clock.
    #[test]
    fn a_short_id_is_the_first_eight_hex_characters_of_sha1() {
        assert_eq!(short_id("abc"), "a9993e36");
        assert_eq!(short_id("abc").len(), ID_LENGTH);
        assert_ne!(short_id("abc"), short_id("abd"));
    }
}
