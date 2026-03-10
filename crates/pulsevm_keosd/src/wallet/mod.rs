use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::fs;

use aes::Aes256;
use cbc::{Encryptor, Decryptor, cipher::{block_padding::Pkcs7, BlockEncryptMut, BlockDecryptMut, KeyIvInit}};
use sha2::{Sha512, Digest};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::{self, KeyError};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

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
}

/// On-disk format for an encrypted wallet file.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct WalletFileData {
    /// AES-256-CBC encrypted blob containing the serialized key map.
    cipher_keys: Vec<u8>,
}

/// Represents a single software wallet, mirroring EOSIO's `soft_wallet`.
pub struct Wallet {
    /// Name of the wallet (used for display and file naming).
    pub name: String,
    /// Path to the .wallet file on disk.
    file_path: PathBuf,
    /// Whether the wallet is currently locked.
    locked: bool,
    /// SHA-512 hash of the password, used to derive AES key.
    checksum: [u8; 64],
    /// Decrypted key map: EOS public key string -> WIF private key string.
    keys: BTreeMap<String, String>,
}

impl Wallet {
    /// Create a brand-new wallet with the given password. Returns the wallet.
    pub fn create(name: &str, password: &str, wallet_dir: &Path) -> Result<Self, WalletError> {
        let file_path = wallet_dir.join(format!("{}.wallet", name));

        let checksum = sha512_hash(password.as_bytes());
        let keys = BTreeMap::new();

        let wallet = Wallet {
            name: name.to_string(),
            file_path,
            locked: false,
            checksum,
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
            checksum: [0u8; 64],
            keys: BTreeMap::new(),
        })
    }

    /// Unlock the wallet with the given password.
    pub fn unlock(&mut self, password: &str) -> Result<(), WalletError> {
        if !self.locked {
            return Err(WalletError::AlreadyUnlocked);
        }

        let checksum = sha512_hash(password.as_bytes());

        // Read and decrypt wallet file
        let file_data = fs::read(&self.file_path)?;
        let wallet_file: WalletFileData = serde_json::from_slice(&file_data)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        let decrypted = decrypt_data(&wallet_file.cipher_keys, &checksum)
            .map_err(|_| WalletError::InvalidPassword(self.name.clone()))?;

        let keys: BTreeMap<String, String> = serde_json::from_slice(&decrypted)
            .map_err(|_| WalletError::InvalidPassword(self.name.clone()))?;

        self.checksum = checksum;
        self.keys = keys;
        self.locked = false;
        Ok(())
    }

    /// Lock the wallet, clearing decrypted keys from memory.
    pub fn lock(&mut self) {
        self.keys.clear();
        self.checksum = [0u8; 64];
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

        // Verify password
        let check = sha512_hash(password.as_bytes());
        if check != self.checksum {
            return Err(WalletError::InvalidPassword(self.name.clone()));
        }

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
        let check = sha512_hash(password.as_bytes());
        if check != self.checksum {
            return Err(WalletError::InvalidPassword(self.name.clone()));
        }
        Ok(self.keys.clone())
    }

    /// Try to sign a digest with a specific public key. Returns the signature hex or None.
    pub fn try_sign_digest(&self, digest: &[u8], public_key: &str) -> Result<Option<String>, WalletError> {
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
        let keys_json = serde_json::to_vec(&self.keys)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        let encrypted = encrypt_data(&keys_json, &self.checksum);

        let wallet_file = WalletFileData {
            cipher_keys: encrypted,
        };

        let data = serde_json::to_vec_pretty(&wallet_file)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Ensure parent directory exists
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.file_path, data)?;
        Ok(())
    }
}

/// Derive a 32-byte AES key and 16-byte IV from the SHA-512 checksum.
fn derive_key_iv(checksum: &[u8; 64]) -> ([u8; 32], [u8; 16]) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&checksum[..32]);
    iv.copy_from_slice(&checksum[32..48]);
    (key, iv)
}

/// Encrypt data using AES-256-CBC with PKCS7 padding.
fn encrypt_data(plaintext: &[u8], checksum: &[u8; 64]) -> Vec<u8> {
    let (key, iv) = derive_key_iv(checksum);
    let encryptor = Aes256CbcEnc::new(&key.into(), &iv.into());
    encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// Decrypt data using AES-256-CBC with PKCS7 padding.
fn decrypt_data(ciphertext: &[u8], checksum: &[u8; 64]) -> Result<Vec<u8>, ()> {
    let (key, iv) = derive_key_iv(checksum);
    let decryptor = Aes256CbcDec::new(&key.into(), &iv.into());
    decryptor.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).map_err(|_| ())
}

fn sha512_hash(data: &[u8]) -> [u8; 64] {
    let result = Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}