//! Encryption of password fields at rest (PORTA.md §13): `ab_peer.hash_enc`, `ab_peer.password_enc`.
//! Protects database files and backups; the operator can still decrypt with `porta_secret.key`.

use hbb_common::{anyhow::Context, bail, ResultType};
use sodiumoxide::crypto::secretbox;
use std::{io::Write, path::Path};

pub const SECRET_KEY_FILE: &str = "porta_secret.key";
const PREFIX: &str = "sb1:";

pub struct SecretBox {
    key: secretbox::Key,
}

impl SecretBox {
    /// Server mode: loads the key (base64 of 32 random bytes), creating it with mode 0600 on first start.
    pub fn load_or_create(path: &Path) -> ResultType<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(path, &text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let key = secretbox::gen_key();
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
                let mut file = options
                    .open(path)
                    .with_context(|| format!("Failed to create {}", path.display()))?;
                file.write_all(base64::encode(key.as_ref()).as_bytes())?;
                file.sync_all()?;
                hbb_common::log::info!("Secret key written to {}", path.display());
                Ok(Self { key })
            }
            Err(err) => Err(err).with_context(|| format!("Failed to read {}", path.display())),
        }
    }

    /// Command line mode (including import): the key must already exist; never creates one.
    pub fn load_existing(path: &Path) -> ResultType<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(path, &text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
                "{} not found: run this from the server's working directory, or start the server once first",
                path.display()
            ),
            Err(err) => Err(err).with_context(|| format!("Failed to read {}", path.display())),
        }
    }

    fn parse(path: &Path, text: &str) -> ResultType<Self> {
        let bytes =
            base64::decode(text.trim()).with_context(|| format!("Malformed {}", path.display()))?;
        let Some(key) = secretbox::Key::from_slice(&bytes) else {
            bail!("Malformed {}: expected {} bytes", path.display(), secretbox::KEYBYTES);
        };
        Ok(Self { key })
    }

    /// `sb1:` + base64(nonce ‖ ciphertext). An empty value stays empty (the column default, "no password").
    pub fn encrypt(&self, plain: &str) -> String {
        if plain.is_empty() {
            return String::new();
        }
        let nonce = secretbox::gen_nonce();
        let mut data = nonce.as_ref().to_vec();
        data.extend(secretbox::seal(plain.as_bytes(), &nonce, &self.key));
        format!("{PREFIX}{}", base64::encode(data))
    }

    pub fn decrypt(&self, stored: &str) -> ResultType<String> {
        if stored.is_empty() {
            return Ok(String::new());
        }
        let Some(b64) = stored.strip_prefix(PREFIX) else {
            bail!("Unknown encrypted value format");
        };
        let data = base64::decode(b64).context("Malformed encrypted value")?;
        if data.len() < secretbox::NONCEBYTES {
            bail!("Malformed encrypted value");
        }
        let (nonce, cipher) = data.split_at(secretbox::NONCEBYTES);
        let Some(nonce) = secretbox::Nonce::from_slice(nonce) else {
            bail!("Malformed encrypted value");
        };
        let Ok(plain) = secretbox::open(cipher, &nonce, &self.key) else {
            bail!("Failed to decrypt value (wrong {SECRET_KEY_FILE}?)");
        };
        Ok(String::from_utf8(plain)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRET_KEY_FILE);
        let sb = SecretBox::load_or_create(&path).unwrap();
        let enc = sb.encrypt("密码 pass");
        assert!(enc.starts_with("sb1:"));
        assert_ne!(enc, sb.encrypt("密码 pass"), "fresh nonce every time");
        assert_eq!(sb.decrypt(&enc).unwrap(), "密码 pass");
        assert_eq!(sb.encrypt(""), "");
        assert_eq!(sb.decrypt("").unwrap(), "");

        let again = SecretBox::load_or_create(&path).unwrap();
        assert_eq!(again.decrypt(&enc).unwrap(), "密码 pass");
        let existing = SecretBox::load_existing(&path).unwrap();
        assert_eq!(existing.decrypt(&enc).unwrap(), "密码 pass");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn rejects_tampering_and_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let a = SecretBox::load_or_create(&dir.path().join("a.key")).unwrap();
        let b = SecretBox::load_or_create(&dir.path().join("b.key")).unwrap();
        let enc = a.encrypt("x");
        assert!(b.decrypt(&enc).is_err());
        assert!(a.decrypt("plain").is_err());
        assert!(a.decrypt("sb1:AAAA").is_err());
        let mut raw = base64::decode(&enc[4..]).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(a.decrypt(&format!("sb1:{}", base64::encode(raw))).is_err());
    }

    #[test]
    fn load_existing_never_creates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRET_KEY_FILE);
        let err = SecretBox::load_existing(&path).err().unwrap().to_string();
        assert!(err.contains("start the server once"));
        assert!(!path.exists());
    }

    #[test]
    fn rejects_malformed_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        std::fs::write(&path, base64::encode([0u8; 16])).unwrap();
        assert!(SecretBox::load_or_create(&path).is_err());
    }
}
