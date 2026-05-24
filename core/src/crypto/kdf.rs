use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::profile::format::ProfileCryptoError;

use super::aead::KEY_LEN;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idConfig {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2idConfig {
    pub const DEFAULT: Self = Self {
        memory_kib: 194_560,
        iterations: 3,
        parallelism: 1,
    };

    /// Upper bounds for KDF parameters accepted before deriving a key.
    /// The envelope header is cleartext (outside the AEAD), so on a
    /// supplied or server-served container these values are
    /// attacker-controlled. The ceilings block a hostile header from
    /// requesting a multi-GB allocation (OOM) or a runaway iteration
    /// count (CPU time-bomb) while staying far above any legitimate
    /// config (`DEFAULT` is 190 MiB / t=3 / p=1).
    ///
    /// No lower *memory* bound is imposed on purpose: a legitimately weak
    /// older container must still decrypt so KDF rotation can upgrade it
    /// (see `profile::rotation`). `iterations`/`parallelism` only need to
    /// be ≥ 1 (Argon2's own minimum). See security audit F3.
    pub const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024; // 2 GiB
    pub const MAX_ITERATIONS: u32 = 16;
    pub const MAX_PARALLELISM: u32 = 8;

    /// Reject parameters outside the sane band before they reach
    /// `Params::new`/`hash_password_into`, turning a DoS into a fast,
    /// explicit error. Does not depend on the passphrase, so it creates
    /// no decrypt oracle.
    pub fn validate(&self) -> Result<(), ProfileCryptoError> {
        if self.memory_kib > Self::MAX_MEMORY_KIB
            || !(1..=Self::MAX_ITERATIONS).contains(&self.iterations)
            || !(1..=Self::MAX_PARALLELISM).contains(&self.parallelism)
        {
            return Err(ProfileCryptoError::Kdf(format!(
                "parameters out of range (memory_kib={}, iterations={}, parallelism={})",
                self.memory_kib, self.iterations, self.parallelism
            )));
        }
        Ok(())
    }
}

impl Default for Argon2idConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

pub(crate) fn derive_key(
    passphrase: &str,
    salt: &[u8],
    config: &Argon2idConfig,
) -> Result<Zeroizing<[u8; KEY_LEN]>, ProfileCryptoError> {
    config.validate()?;

    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| ProfileCryptoError::Kdf(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| ProfileCryptoError::Kdf("hash_password_into failed".into()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        assert!(Argon2idConfig::DEFAULT.validate().is_ok());
    }

    #[test]
    fn legitimately_weak_config_still_validates() {
        // KDF rotation must be able to decrypt old, weak containers in
        // order to upgrade them — so a small memory/iteration config is
        // accepted (these mirror the fixtures in `profile::rotation`).
        let weak = Argon2idConfig { memory_kib: 1024, iterations: 1, parallelism: 1 };
        assert!(weak.validate().is_ok());
        let weak2 = Argon2idConfig { memory_kib: 2048, iterations: 2, parallelism: 1 };
        assert!(weak2.validate().is_ok());
    }

    #[test]
    fn hostile_params_are_rejected() {
        // ~190 GB allocation request → would OOM at hash_password_into.
        let oom = Argon2idConfig { memory_kib: 200_000_000, iterations: 3, parallelism: 1 };
        assert!(oom.validate().is_err());
        // Runaway iteration count → CPU time-bomb.
        let bomb = Argon2idConfig { memory_kib: 194_560, iterations: u32::MAX, parallelism: 1 };
        assert!(bomb.validate().is_err());
        // Absurd parallelism.
        let par = Argon2idConfig { memory_kib: 194_560, iterations: 3, parallelism: 1000 };
        assert!(par.validate().is_err());
    }

    #[test]
    fn zero_iterations_or_parallelism_rejected() {
        assert!(
            Argon2idConfig { memory_kib: 8192, iterations: 0, parallelism: 1 }
                .validate()
                .is_err()
        );
        assert!(
            Argon2idConfig { memory_kib: 8192, iterations: 1, parallelism: 0 }
                .validate()
                .is_err()
        );
    }
}
