use std::{
    collections::BTreeMap,
    fs::{
        self,
        OpenOptions,
    },
    io::Write,
    path::{
        Path,
        PathBuf,
    },
};

use aes::Aes256;
use aes_gcm::{
    Aes256Gcm,
    Nonce,
    aead::{
        Aead,
        KeyInit,
        Payload,
    },
};
use argon2::{
    Algorithm,
    Argon2,
    Params,
    Version,
};
use cbc::{
    Decryptor,
    cipher::{
        BlockDecryptMut,
        KeyIvInit,
        block_padding::Pkcs7,
    },
};
#[cfg(test)]
use cbc::{
    Encryptor,
    cipher::BlockEncryptMut,
};
use rand::RngCore;
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest,
    Sha512,
};
use subtle::ConstantTimeEq;
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
    Zeroizing,
};

use crate::keys::{
    self,
    KeyError,
};

#[cfg(test)]
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const WALLET_FORMAT_VERSION: u8 = 2;
const KDF_ALGORITHM: &str = "argon2id";
const CIPHER_ALGORITHM: &str = "aes-256-gcm";
const WALLET_AAD: &[u8] = b"pulsevm-keosd-wallet-v2";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const DEFAULT_MEMORY_KIB: u32 = 19_456;
const DEFAULT_ITERATIONS: u32 = 2;
const DEFAULT_PARALLELISM: u32 = 1;
const MAX_MEMORY_KIB: u32 = 65_536;
const MAX_ITERATIONS: u32 = 5;
const MAX_PARALLELISM: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Wallet is locked")]
    Locked,
    #[error("Wallet is already unlocked")]
    AlreadyUnlocked,
    #[error("Invalid password for wallet: \"{0}\"")]
    InvalidPassword(String),
    #[error("Key already exists in wallet")]
    KeyAlreadyExists,
    #[error("Key not found in wallet")]
    KeyNotFound,
    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid path: {0}")]
    PathError(String),
}

/// Current on-disk format for an encrypted wallet file.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct WalletFileData {
    version: u8,
    kdf: WalletKdfData,
    cipher: String,
    nonce: Vec<u8>,
    /// Authenticated encrypted blob containing the serialized key map.
    cipher_keys: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct WalletKdfData {
    algorithm: String,
    salt: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// Original keosd format, retained only so an authenticated unlock can migrate it.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct LegacyWalletFileData {
    cipher_keys: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredWalletFileData {
    Current(WalletFileData),
    Legacy(LegacyWalletFileData),
}

/// Represents a single software wallet, mirroring EOSIO's `soft_wallet`.
pub struct Wallet {
    /// Name of the wallet (used for display and file naming).
    pub name: String,
    /// Path to the .wallet file on disk.
    file_path: PathBuf,
    /// Whether the wallet is currently locked.
    locked: bool,
    /// Argon2id-derived encryption key, present only while unlocked.
    encryption_key: [u8; KEY_LEN],
    /// Parameters required to verify the password and persist the current format.
    kdf: Option<WalletKdfData>,
    /// Decrypted key map: EOS public key string -> WIF private key string.
    keys: BTreeMap<String, String>,
}

impl Wallet {
    /// Create a brand-new wallet with the given password. Returns the wallet.
    pub fn create(name: &str, password: &str, wallet_dir: &Path) -> Result<Self, WalletError> {
        // Reject names with path separators or traversal sequences
        if name.contains('/') || name.contains('\\') || name.contains('.') {
            return Err(WalletError::PathError("name rejected".to_string()));
        }

        let file_path = wallet_dir.join(format!("{}.wallet", name));

        // Defense-in-depth against path traversal: resolve the target
        // *directory* (the wallet file itself does not exist yet, so it
        // cannot be canonicalized) and confirm the wallet file lands
        // inside it. The name check above already rejects separators and
        // dots, so this is belt-and-suspenders.
        fs::create_dir_all(wallet_dir)?;
        let canonical_dir = wallet_dir.canonicalize()?;
        if !canonical_dir
            .join(format!("{}.wallet", name))
            .starts_with(&canonical_dir)
        {
            return Err(WalletError::PathError("name rejected".to_string()));
        }

        let kdf = WalletKdfData::new();
        let encryption_key = derive_password_key(password, &kdf)?;
        let keys = BTreeMap::new();

        let wallet = Wallet {
            name: name.to_string(),
            file_path,
            locked: false,
            encryption_key,
            kdf: Some(kdf),
            keys,
        };

        wallet.save_to_disk()?;
        Ok(wallet)
    }

    /// Open an existing wallet from disk (loads in locked state).
    pub fn open(name: &str, wallet_dir: &Path) -> Result<Self, WalletError> {
        let file_path = wallet_dir.join(format!("{}.wallet", name));
        if !file_path.exists() {
            return Err(WalletError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Wallet file not found: {}", file_path.display()),
            )));
        }

        Ok(Wallet {
            name: name.to_string(),
            file_path,
            locked: true,
            encryption_key: [0u8; KEY_LEN],
            kdf: None,
            keys: BTreeMap::new(),
        })
    }

    /// Unlock the wallet with the given password.
    pub fn unlock(&mut self, password: &str) -> Result<(), WalletError> {
        if !self.locked {
            return Err(WalletError::AlreadyUnlocked);
        }

        let file_data = fs::read(&self.file_path)?;
        let wallet_file: StoredWalletFileData = serde_json::from_slice(&file_data)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        match wallet_file {
            StoredWalletFileData::Current(wallet_file) => {
                self.unlock_current(password, wallet_file)
            }
            StoredWalletFileData::Legacy(wallet_file) => {
                self.unlock_and_migrate_legacy(password, wallet_file)
            }
        }
    }

    /// Lock the wallet, clearing decrypted keys from memory.
    pub fn lock(&mut self) {
        self.clear_sensitive_state();
        self.locked = true;
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Import a WIF private key. Returns the corresponding EOS public key.
    pub fn import_key(&mut self, wif: &str) -> Result<String, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        let sk = keys::wif_to_private_key(wif)?;
        let pub_key = keys::pub_k1_string(&sk);

        if self.keys.contains_key(&pub_key) {
            return Err(WalletError::KeyAlreadyExists);
        }

        self.keys.insert(pub_key.clone(), wif.to_string());
        self.save_to_disk()?;
        Ok(pub_key)
    }

    /// Create a new key pair inside the wallet. Returns the EOS public key.
    pub fn create_key(&mut self) -> Result<String, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        let (wif, pub_key) = keys::generate_keypair()?;
        self.keys.insert(pub_key.clone(), wif);
        self.save_to_disk()?;
        Ok(pub_key)
    }

    /// Remove a key by its EOS public key string.
    pub fn remove_key(&mut self, password: &str, public_key: &str) -> Result<(), WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        self.verify_password(password)?;

        if self.keys.remove(public_key).is_none() {
            return Err(WalletError::KeyNotFound);
        }

        self.save_to_disk()?;
        Ok(())
    }

    /// List all public keys (wallet must be unlocked).
    pub fn list_public_keys(&self) -> Result<Vec<String>, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }
        Ok(self.keys.keys().cloned().collect())
    }

    /// List all key pairs (public -> private) - requires password verification.
    pub fn list_keys(&self, password: &str) -> Result<BTreeMap<String, String>, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }
        self.verify_password(password)?;
        Ok(self.keys.clone())
    }

    /// Try to sign a digest with a specific public key. Returns the signature hex or None.
    pub fn try_sign_digest(
        &self,
        digest: &[u8],
        public_key: &str,
    ) -> Result<Option<String>, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }
        match self.keys.get(public_key) {
            Some(wif) => {
                let sk = keys::wif_to_private_key(wif)?;
                let sig = keys::sign_digest(&sk, digest)?;
                Ok(Some(sig))
            }
            None => Ok(None),
        }
    }

    /// Encrypt and write the wallet to disk.
    fn save_to_disk(&self) -> Result<(), WalletError> {
        let keys_json = Zeroizing::new(
            serde_json::to_vec(&self.keys)
                .map_err(|e| WalletError::SerializationError(e.to_string()))?,
        );

        let kdf = self.kdf.as_ref().ok_or(WalletError::Locked)?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let encrypted = encrypt_current(&keys_json, &self.encryption_key, &nonce)?;

        let wallet_file = WalletFileData {
            version: WALLET_FORMAT_VERSION,
            kdf: kdf.clone(),
            cipher: CIPHER_ALGORITHM.to_string(),
            nonce: nonce.to_vec(),
            cipher_keys: encrypted,
        };

        let data = serde_json::to_vec_pretty(&wallet_file)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write_private(&self.file_path, &data)
    }

    fn unlock_current(
        &mut self,
        password: &str,
        wallet_file: WalletFileData,
    ) -> Result<(), WalletError> {
        wallet_file.validate()?;
        let encryption_key = Zeroizing::new(derive_password_key(password, &wallet_file.kdf)?);
        let decrypted = decrypt_current(
            &wallet_file.cipher_keys,
            &encryption_key,
            &wallet_file.nonce,
        )
        .map_err(|_| WalletError::InvalidPassword(self.name.clone()))?;
        let keys = parse_decrypted_keys(decrypted, &self.name)?;

        self.encryption_key.copy_from_slice(&encryption_key[..]);
        self.kdf = Some(wallet_file.kdf.clone());
        self.keys = keys;
        self.locked = false;
        Ok(())
    }

    fn unlock_and_migrate_legacy(
        &mut self,
        password: &str,
        wallet_file: LegacyWalletFileData,
    ) -> Result<(), WalletError> {
        let checksum = Zeroizing::new(sha512_hash(password.as_bytes()));
        let decrypted = decrypt_legacy(&wallet_file.cipher_keys, &checksum)
            .map_err(|_| WalletError::InvalidPassword(self.name.clone()))?;
        let keys = parse_decrypted_keys(decrypted, &self.name)?;
        let kdf = WalletKdfData::new();
        let encryption_key = Zeroizing::new(derive_password_key(password, &kdf)?);
        self.encryption_key.copy_from_slice(&encryption_key[..]);
        self.kdf = Some(kdf);
        self.keys = keys;
        self.locked = false;

        if let Err(error) = self.save_to_disk() {
            self.lock();
            return Err(error);
        }
        Ok(())
    }

    fn verify_password(&self, password: &str) -> Result<(), WalletError> {
        let kdf = self.kdf.as_ref().ok_or(WalletError::Locked)?;
        let mut candidate = derive_password_key(password, kdf)?;
        let matches = bool::from(candidate.ct_eq(&self.encryption_key));
        candidate.zeroize();
        if !matches {
            return Err(WalletError::InvalidPassword(self.name.clone()));
        }
        Ok(())
    }

    fn clear_sensitive_state(&mut self) {
        for private_key in self.keys.values_mut() {
            private_key.zeroize();
        }
        self.keys.clear();
        self.encryption_key.zeroize();
        self.kdf = None;
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.clear_sensitive_state();
    }
}

impl WalletKdfData {
    fn new() -> Self {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        Self {
            algorithm: KDF_ALGORITHM.to_string(),
            salt: salt.to_vec(),
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
        }
    }

    fn validate(&self) -> Result<(), WalletError> {
        if self.algorithm != KDF_ALGORITHM
            || self.salt.len() != SALT_LEN
            || self.memory_kib < DEFAULT_MEMORY_KIB
            || self.memory_kib > MAX_MEMORY_KIB
            || self.iterations < DEFAULT_ITERATIONS
            || self.iterations > MAX_ITERATIONS
            || self.parallelism == 0
            || self.parallelism > MAX_PARALLELISM
        {
            return Err(WalletError::SerializationError(
                "unsupported or unsafe wallet KDF parameters".to_string(),
            ));
        }
        Ok(())
    }
}

impl WalletFileData {
    fn validate(&self) -> Result<(), WalletError> {
        if self.version != WALLET_FORMAT_VERSION
            || self.cipher != CIPHER_ALGORITHM
            || self.nonce.len() != NONCE_LEN
        {
            return Err(WalletError::SerializationError(
                "unsupported wallet file format".to_string(),
            ));
        }
        self.kdf.validate()
    }
}

fn derive_password_key(password: &str, kdf: &WalletKdfData) -> Result<[u8; KEY_LEN], WalletError> {
    kdf.validate()?;
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| WalletError::SerializationError(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), &kdf.salt, &mut key[..])
        .map_err(|e| WalletError::SerializationError(e.to_string()))?;
    Ok(*key)
}

fn encrypt_current(
    plaintext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, WalletError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WalletError::SerializationError(e.to_string()))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: WALLET_AAD,
            },
        )
        .map_err(|_| WalletError::SerializationError("wallet encryption failed".to_string()))
}

fn decrypt_current(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: WALLET_AAD,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ())
}

fn parse_decrypted_keys(
    decrypted: Zeroizing<Vec<u8>>,
    wallet_name: &str,
) -> Result<BTreeMap<String, String>, WalletError> {
    serde_json::from_slice(&decrypted)
        .map_err(|_| WalletError::InvalidPassword(wallet_name.to_string()))
}

fn atomic_write_private(path: &Path, data: &[u8]) -> Result<(), WalletError> {
    let parent = path
        .parent()
        .ok_or_else(|| WalletError::PathError("wallet file has no parent directory".to_string()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| WalletError::PathError("wallet file has an invalid name".to_string()))?;
    let mut random_suffix = [0u8; 16];
    rand::rng().fill_bytes(&mut random_suffix);
    let temporary_path = parent.join(format!(".{file_name}.{}.tmp", hex::encode(random_suffix)));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let result = (|| -> Result<(), std::io::Error> {
        let mut file = options.open(&temporary_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary_path, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result.map_err(WalletError::IoError)
}

/// Derive the AES key and IV used by the original wallet format.
fn derive_legacy_key_iv(checksum: &[u8; 64]) -> ([u8; 32], [u8; 16]) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&checksum[..32]);
    iv.copy_from_slice(&checksum[32..48]);
    (key, iv)
}

#[cfg(test)]
fn encrypt_legacy(plaintext: &[u8], checksum: &[u8; 64]) -> Vec<u8> {
    let (key, iv) = derive_legacy_key_iv(checksum);
    let encryptor = Aes256CbcEnc::new(&key.into(), &iv.into());
    encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

fn decrypt_legacy(ciphertext: &[u8], checksum: &[u8; 64]) -> Result<Zeroizing<Vec<u8>>, ()> {
    let (key, iv) = derive_legacy_key_iv(checksum);
    let key = Zeroizing::new(key);
    let iv = Zeroizing::new(iv);
    let decryptor = Aes256CbcDec::new_from_slices(&key[..], &iv[..]).map_err(|_| ())?;
    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| ())
}

fn sha512_hash(data: &[u8]) -> [u8; 64] {
    let result = Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn new_wallet_uses_authenticated_versioned_format() {
        let directory = TempDir::new().unwrap();
        let wallet = Wallet::create("secure", "correct horse", directory.path()).unwrap();
        let path = directory.path().join("secure.wallet");
        let stored: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        assert_eq!(stored["version"], WALLET_FORMAT_VERSION);
        assert_eq!(stored["kdf"]["algorithm"], KDF_ALGORITHM);
        assert_eq!(stored["cipher"], CIPHER_ALGORITHM);
        assert_eq!(stored["kdf"]["salt"].as_array().unwrap().len(), SALT_LEN);
        assert_eq!(stored["nonce"].as_array().unwrap().len(), NONCE_LEN);
        assert!(!wallet.is_locked());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("secure.wallet");
        Wallet::create("secure", "correct horse", directory.path()).unwrap();
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored["cipher_keys"][0] = json!(stored["cipher_keys"][0].as_u64().unwrap() ^ 1);
        fs::write(&path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

        let mut wallet = Wallet::open("secure", directory.path()).unwrap();
        assert!(matches!(
            wallet.unlock("correct horse"),
            Err(WalletError::InvalidPassword(_))
        ));
        assert!(wallet.is_locked());
    }

    #[test]
    fn legacy_wallet_is_migrated_after_unlock() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("legacy.wallet");
        let password = "old password";
        let checksum = sha512_hash(password.as_bytes());
        let plaintext = serde_json::to_vec(&BTreeMap::<String, String>::new()).unwrap();
        let legacy = json!({ "cipher_keys": encrypt_legacy(&plaintext, &checksum) });
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let mut wallet = Wallet::open("legacy", directory.path()).unwrap();
        wallet.unlock(password).unwrap();

        let migrated: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(migrated["version"], WALLET_FORMAT_VERSION);
        assert_eq!(migrated["kdf"]["algorithm"], KDF_ALGORITHM);
        assert_eq!(migrated["cipher"], CIPHER_ALGORITHM);
    }

    #[test]
    fn every_save_uses_a_fresh_nonce() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("secure.wallet");
        let mut wallet = Wallet::create("secure", "correct horse", directory.path()).unwrap();
        let first: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        wallet.create_key().unwrap();
        let second: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();

        assert_ne!(first["nonce"], second["nonce"]);
        assert_eq!(first["kdf"]["salt"], second["kdf"]["salt"]);
    }
}
