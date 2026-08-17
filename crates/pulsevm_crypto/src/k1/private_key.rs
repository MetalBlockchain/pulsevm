use core::ffi::c_void;

use secp256k1::{
    SECP256K1,
    SecretKey,
    ffi::{
        self,
        recovery::{
            RecoverableSignature as FfiRecoverableSignature,
            secp256k1_ecdsa_recoverable_signature_serialize_compact,
            secp256k1_ecdsa_sign_recoverable,
        },
        types::{
            c_int,
            c_uchar,
            c_uint,
        },
    },
};
use sha2::{
    Digest as _,
    Sha256,
};

use super::{
    K1_SUFFIX,
    K1Error,
    K1PublicKey,
    K1Signature,
    decode_b58_checked,
    encode_b58_checked,
};

/// A secp256k1 private key in the EOSIO/Antelope `K1` encoding.
///
/// The canonical in-memory form is the 32-byte scalar (fc's
/// `private_key_secret`, a `sha256`).
#[derive(Clone)]
pub struct K1PrivateKey {
    secret: SecretKey,
}

impl K1PrivateKey {
    /// Build from a 32-byte scalar.
    pub fn from_scalar(bytes: &[u8; 32]) -> Result<Self, K1Error> {
        Ok(K1PrivateKey {
            secret: SecretKey::from_slice(bytes)?,
        })
    }

    /// The 32-byte scalar.
    pub fn scalar(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }

    /// A freshly-generated random K1 key (OS entropy). For tests and tooling.
    pub fn random() -> Self {
        let (secret, _public) = SECP256K1.generate_keypair(&mut secp256k1::rand::thread_rng());
        K1PrivateKey { secret }
    }

    /// fc `make_k1_private_key(make_shared_digest_from_string(s))`:
    /// deterministically derive a key from a seed string by taking the sha256
    /// of the UTF-8 bytes as the scalar.
    pub fn from_seed_string(s: &str) -> Result<Self, K1Error> {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let digest = hasher.finalize();
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&digest);
        Self::from_scalar(&scalar)
    }

    /// The compressed public key for this private key.
    pub fn public_key(&self) -> K1PublicKey {
        let pk = secp256k1::PublicKey::from_secret_key(SECP256K1, &self.secret);
        K1PublicKey::from_secp(&pk)
    }

    /// The modern `PVT_K1_...` string form.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let scalar = self.scalar();
        format!("PVT_K1_{}", encode_b58_checked(&scalar, K1_SUFFIX))
    }

    /// Parse a private key string.
    ///
    /// The modern `PVT_K1_...` form is what the C++ `parse_private_key` path
    /// accepts. Legacy Bitcoin-WIF (`5...`) keys are also accepted here for
    /// convenience even though the C++ oracle's parse path does not reach them.
    pub fn from_string(s: &str) -> Result<Self, K1Error> {
        if let Some(data) = s.strip_prefix("PVT_K1_") {
            let bytes = decode_b58_checked(data, 32, K1_SUFFIX)?;
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&bytes);
            return Self::from_scalar(&scalar);
        }
        // Legacy WIF: base58(0x80 || scalar || sha256(sha256(0x80||scalar))[..4]).
        Self::from_wif(s)
    }

    fn from_wif(s: &str) -> Result<Self, K1Error> {
        let raw = bs58::decode(s).into_vec().map_err(|_| K1Error::BadBase58)?;
        if raw.len() != 37 || raw[0] != 0x80 {
            return Err(K1Error::BadLength);
        }
        let (body, checksum) = raw.split_at(33);
        let mut h1 = Sha256::new();
        h1.update(body);
        let d1 = h1.finalize();
        let mut h2 = Sha256::new();
        h2.update(d1);
        let d2 = h2.finalize();
        if d2[..4] != *checksum {
            return Err(K1Error::BadChecksum);
        }
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&body[1..]);
        Self::from_scalar(&scalar)
    }

    /// Sign a 32-byte digest, producing a canonical recoverable `K1` signature.
    ///
    /// This reproduces fc's `sign_compact(digest, require_canonical=true)`
    /// byte-for-byte: it drives libsecp256k1's recoverable signing with the same
    /// `extended_nonce_function` (an RFC6979 nonce whose attempt counter is
    /// bumped every invocation and shared across the canonical-retry loop),
    /// and re-signs until fc's `is_canonical` predicate holds.
    pub fn sign(&self, digest: &[u8; 32]) -> K1Signature {
        let seckey = self.secret.secret_bytes();
        // The shared counter fc keeps as `unsigned int counter = 0;`.
        let mut counter: c_uint = 0;
        loop {
            let mut raw = FfiRecoverableSignature::new();
            let mut recid: c_int = 0;
            let mut out64 = [0u8; 64];
            unsafe {
                let ok = secp256k1_ecdsa_sign_recoverable(
                    SECP256K1.ctx().as_ptr(),
                    &mut raw,
                    digest.as_ptr() as *const c_uchar,
                    seckey.as_ptr() as *const c_uchar,
                    Some(fc_extended_nonce_function),
                    &mut counter as *mut c_uint as *const c_void,
                );
                assert_eq!(ok, 1, "secp256k1_ecdsa_sign_recoverable failed");
                let ok = secp256k1_ecdsa_recoverable_signature_serialize_compact(
                    SECP256K1.ctx().as_ptr(),
                    out64.as_mut_ptr() as *mut c_uchar,
                    &mut recid,
                    &raw,
                );
                assert_eq!(ok, 1, "serialize_compact failed");
            }
            let mut compact = [0u8; 65];
            compact[0] = (27 + 4 + recid) as u8;
            compact[1..].copy_from_slice(&out64);
            let sig = K1Signature::from_compact65(&compact);
            if sig.is_canonical() {
                return sig;
            }
        }
    }
}

impl core::fmt::Debug for K1PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("K1PrivateKey")
            .field("public_key", &self.public_key())
            .finish()
    }
}

/// Mirror of fc's `extended_nonce_function`: bump the shared counter and defer
/// to libsecp256k1's default RFC6979 nonce, passing the counter as the attempt.
unsafe extern "C" fn fc_extended_nonce_function(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    key32: *const c_uchar,
    algo16: *const c_uchar,
    data: *mut c_void,
    _attempt: c_uint,
) -> c_int {
    unsafe {
        let extra = data as *mut c_uint;
        *extra = (*extra).wrapping_add(1);
        let default = ffi::secp256k1_nonce_function_default
            .expect("libsecp256k1 default nonce function present");
        default(nonce32, msg32, key32, algo16, core::ptr::null_mut(), *extra)
    }
}
