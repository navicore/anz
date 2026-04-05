use anyhow::Result;
use argon2::Argon2;
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Hash a password with Argon2id.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash. Returns true if it matches.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Perform a dummy hash to prevent timing oracle on unknown usernames.
pub fn dummy_verify() {
    let dummy_hash =
        "$argon2id$v=19$m=19456,t=2,p=1$dW5rbm93bg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let _ = verify_password("dummy", dummy_hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("secret123").unwrap();
        assert!(verify_password("secret123", &hash));
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("correct").unwrap();
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn invalid_hash_returns_false() {
        assert!(!verify_password("anything", "not-a-valid-hash"));
    }

    #[test]
    fn dummy_verify_does_not_panic() {
        dummy_verify();
    }
}
