pub mod csrf;
pub mod keys;
pub mod password;
pub mod pkce;
pub mod token;

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
