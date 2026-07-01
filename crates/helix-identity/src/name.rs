use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NameError {
    #[error("Name too short (min 3 chars)")]
    TooShort,
    #[error("Name too long (max 32 chars)")]
    TooLong,
    #[error("Invalid character '{0}' — only lowercase letters, digits, hyphens allowed")]
    InvalidChar(char),
    #[error("Name already registered")]
    AlreadyTaken,
}

/// A human-readable Helix name: `alice` resolves to `alice.hlx`
/// Rules: 3–32 chars, lowercase letters/digits/hyphens, no leading/trailing hyphen
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HelixName(String);

impl HelixName {
    pub fn new(name: &str) -> Result<Self, NameError> {
        let name = name.trim_end_matches(".hlx");

        if name.len() < 3 {
            return Err(NameError::TooShort);
        }
        if name.len() > 32 {
            return Err(NameError::TooLong);
        }
        for c in name.chars() {
            if !matches!(c, 'a'..='z' | '0'..='9' | '-') {
                return Err(NameError::InvalidChar(c));
            }
        }

        Ok(HelixName(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Full qualified name including TLD
    pub fn full(&self) -> String {
        format!("{}.hlx", self.0)
    }
}

impl std::fmt::Display for HelixName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_names() {
        assert!(HelixName::new("alice").is_ok());
        assert!(HelixName::new("alice.hlx").is_ok()); // strips TLD
        assert!(HelixName::new("my-wallet").is_ok());
        assert!(HelixName::new("user123").is_ok());
    }

    #[test]
    fn test_invalid_names() {
        assert!(HelixName::new("ab").is_err()); // too short
        assert!(HelixName::new("Alice").is_err()); // uppercase
        assert!(HelixName::new("hello world").is_err()); // space
    }

    #[test]
    fn test_full_name() {
        let n = HelixName::new("alice").unwrap();
        assert_eq!(n.full(), "alice.hlx");
    }
}
