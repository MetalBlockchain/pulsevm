use std::{collections::BTreeMap, fs, path::PathBuf, time::{Duration, Instant}};

use crate::wallet::{Wallet, WalletError};

#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("Wallet already exists: {0}")]
    WalletAlreadyExists(String),
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),
    #[error("Wallet error: {0}")]
    WalletError(#[from] WalletError),
    #[error("No unlocked wallets")]
    NoUnlockedWallets,
    #[error("Public key not found in unlocked wallets: {0}")]
    PublicKeyNotFound(String),
    #[error("Lock file error: {0}")]
    LockFileError(String),
}

pub struct WalletManager {
    wallets: BTreeMap<String, Wallet>,
    wallet_dir: PathBuf,
    timeout: Duration,
    last_activity: Instant,
}

impl WalletManager {
    pub fn new(wallet_dir: PathBuf, timeout_secs: u64) -> Result<Self, ManagerError> {
        // Create wallet directory if it doesn't exist
        fs::create_dir_all(&wallet_dir)
            .map_err(|e| ManagerError::LockFileError(e.to_string()))?;

        Ok(WalletManager {
            wallets: BTreeMap::new(),
            wallet_dir,
            timeout: Duration::from_secs(timeout_secs),
            last_activity: Instant::now(),
        })
    }

    /// Check and enforce auto-lock timeout.
    fn check_timeout(&mut self) {
        if self.timeout.as_secs() > 0 && self.last_activity.elapsed() > self.timeout {
            self.lock_all_wallets();
        }
        self.last_activity = Instant::now();
    }

    /// Create a new wallet. Returns the generated password.
    pub fn create(&mut self, name: &str) -> Result<String, ManagerError> {
        self.check_timeout();

        if self.wallets.contains_key(name) {
            return Err(ManagerError::WalletAlreadyExists(name.to_string()));
        }

        // Check if wallet file already exists on disk
        let file_path = self.wallet_dir.join(format!("{}.wallet", name));
        if file_path.exists() {
            return Err(ManagerError::WalletAlreadyExists(name.to_string()));
        }

        // Generate a random password
        let password = generate_password();

        let wallet = Wallet::create(name, &password, &self.wallet_dir)?;
        self.wallets.insert(name.to_string(), wallet);

        Ok(password)
    }

    /// Open an existing wallet file.
    pub fn open(&mut self, name: &str) -> Result<(), ManagerError> {
        self.check_timeout();

        if self.wallets.contains_key(name) {
            return Ok(()); // Already open
        }

        let wallet = Wallet::open(name, &self.wallet_dir)?;
        self.wallets.insert(name.to_string(), wallet);
        Ok(())
    }

    /// List all opened wallets. Names with '*' suffix indicate unlocked wallets.
    pub fn list_wallets(&mut self) -> Vec<String> {
        self.check_timeout();

        self.wallets
            .iter()
            .map(|(name, w)| {
                if w.is_locked() {
                    name.clone()
                } else {
                    format!("{} *", name)
                }
            })
            .collect()
    }

    /// Lock a specific wallet.
    pub fn lock(&mut self, name: &str) -> Result<(), ManagerError> {
        self.check_timeout();

        let wallet = self.wallets.get_mut(name)
            .ok_or_else(|| ManagerError::WalletNotFound(name.to_string()))?;

        wallet.lock();
        Ok(())
    }

    /// Lock all wallets.
    pub fn lock_all_wallets(&mut self) {
        for wallet in self.wallets.values_mut() {
            wallet.lock();
        }
    }

    /// Lock all (public API version).
    pub fn lock_all(&mut self) -> Result<(), ManagerError> {
        self.check_timeout();
        self.lock_all_wallets();
        Ok(())
    }

    /// Unlock a wallet with the given password.
    pub fn unlock(&mut self, name: &str, password: &str) -> Result<(), ManagerError> {
        self.check_timeout();

        // Auto-open if not yet open
        if !self.wallets.contains_key(name) {
            self.open(name)?;
        }

        let wallet = self.wallets.get_mut(name)
            .ok_or_else(|| ManagerError::WalletNotFound(name.to_string()))?;

        wallet.unlock(password)?;
        Ok(())
    }

    /// Import a WIF private key into the named wallet.
    pub fn import_key(&mut self, name: &str, wif: &str) -> Result<(), ManagerError> {
        self.check_timeout();

        let wallet = self.wallets.get_mut(name)
            .ok_or_else(|| ManagerError::WalletNotFound(name.to_string()))?;

        wallet.import_key(wif)?;
        Ok(())
    }

    /// Remove a key from a wallet (requires password).
    pub fn remove_key(&mut self, name: &str, password: &str, public_key: &str) -> Result<(), ManagerError> {
        self.check_timeout();

        let wallet = self.wallets.get_mut(name)
            .ok_or_else(|| ManagerError::WalletNotFound(name.to_string()))?;

        wallet.remove_key(password, public_key)?;
        Ok(())
    }

    /// Create a new key pair inside the named wallet. Returns the public key.
    pub fn create_key(&mut self, name: &str) -> Result<String, ManagerError> {
        self.check_timeout();

        let wallet = self.wallets.get_mut(name)
            .ok_or_else(|| ManagerError::WalletNotFound(name.to_string()))?;

        let pub_key = wallet.create_key()?;
        Ok(pub_key)
    }

    /// List keys for a specific wallet (requires name and password).
    pub fn list_keys(&mut self, name: &str, password: &str) -> Result<BTreeMap<String, String>, ManagerError> {
        self.check_timeout();

        let wallet = self.wallets.get(name)
            .ok_or_else(|| ManagerError::WalletNotFound(name.to_string()))?;

        let keys = wallet.list_keys(password)?;
        Ok(keys)
    }

    /// Get all public keys from all unlocked wallets.
    pub fn get_public_keys(&mut self) -> Result<Vec<String>, ManagerError> {
        self.check_timeout();

        let mut all_keys = Vec::new();
        let mut has_unlocked = false;

        for wallet in self.wallets.values() {
            if !wallet.is_locked() {
                has_unlocked = true;
                if let Ok(keys) = wallet.list_public_keys() {
                    all_keys.extend(keys);
                }
            }
        }

        if !has_unlocked {
            return Err(ManagerError::NoUnlockedWallets);
        }

        all_keys.sort();
        all_keys.dedup();
        Ok(all_keys)
    }

    /// Sign a digest with the key matching one of the provided public keys.
    pub fn sign_digest(&mut self, digest: &[u8], public_keys: &[String]) -> Result<BTreeMap<String, String>, ManagerError> {
        self.check_timeout();

        let mut signatures = BTreeMap::new();

        for pubkey in public_keys {
            let mut found = false;
            for wallet in self.wallets.values() {
                if wallet.is_locked() {
                    continue;
                }
                if let Ok(Some(sig)) = wallet.try_sign_digest(digest, pubkey) {
                    signatures.insert(pubkey.clone(), sig);
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(ManagerError::PublicKeyNotFound(pubkey.clone()));
            }
        }

        Ok(signatures)
    }

    /// Set the auto-lock timeout (in seconds).
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout = Duration::from_secs(secs);
        self.last_activity = Instant::now();
    }
}

/// Generate a random password prefixed with "PW" (like EOSIO).
fn generate_password() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    // Use base58 encoding for the password (EOS-style with "PW" prefix)
    format!("PW{}", bs58::encode(bytes).into_string())
}