use std::fmt;

use zeroize::Zeroizing;

pub(crate) struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub(crate) fn expose(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("len", &self.bytes.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretBytes::new(b"private-material".to_vec());
        let debug = format!("{secret:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private-material"));
        assert_eq!(secret.expose(), b"private-material");
    }
}
