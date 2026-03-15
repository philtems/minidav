use sha2::{Sha256, Digest};
use hex;

pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

pub fn is_hashed(password: &str) -> bool {
    password.len() == 64 && password.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn verify_password(plain: &str, hashed: &str) -> bool {
    if is_hashed(hashed) {
        hash_password(plain) == hashed
    } else {
        plain == hashed
    }
}

