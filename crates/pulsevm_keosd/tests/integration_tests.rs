use actix_web::{web, App};
use tempfile::TempDir;

// ============================================================================
// Keys module tests
// ============================================================================

mod key_tests {
    use pulsevm_keosd::keys;

    #[test]
    fn generate_keypair_returns_valid_formats() {
        let (wif, pubkey) = keys::generate_keypair().unwrap();
        // WIF keys for uncompressed start with '5', compressed with 'K' or 'L'
        assert!(
            wif.starts_with('5') || wif.starts_with('K') || wif.starts_with('L'),
            "WIF key has unexpected prefix: {}",
            wif
        );
        assert!(pubkey.starts_with("PUB_K1_"), "Public key missing PUB_K1_ prefix: {}", pubkey);
        // PUB_K1_ public keys are ~50-53 chars
        assert!(pubkey.len() > 45 && pubkey.len() < 60, "Unexpected pubkey length: {}", pubkey.len());
    }

    #[test]
    fn wif_roundtrip() {
        let (wif, pubkey) = keys::generate_keypair().unwrap();
        let sk = keys::wif_to_private_key(&wif).unwrap();
        let pubkey_again = keys::eos_public_key_string(&sk);
        assert_eq!(pubkey, pubkey_again);
    }

    #[test]
    fn public_key_parse_roundtrip() {
        let (_, pubkey) = keys::generate_keypair().unwrap();
        let raw = keys::parse_eos_public_key(&pubkey).unwrap();
        assert_eq!(raw.len(), 33, "Compressed public key should be 33 bytes");
    }

    #[test]
    fn invalid_wif_rejected() {
        assert!(keys::wif_to_private_key("notavalidwif").is_err());
        assert!(keys::wif_to_private_key("").is_err());
        assert!(keys::wif_to_private_key("5").is_err());
    }

    #[test]
    fn invalid_public_key_rejected() {
        assert!(keys::parse_eos_public_key("notavalidkey").is_err());
        assert!(keys::parse_eos_public_key("EOS").is_err());
        assert!(keys::parse_eos_public_key("EOSinvaliddata").is_err());
        assert!(keys::parse_eos_public_key("").is_err());
    }

    #[test]
    fn sign_digest_produces_output() {
        let (wif, _) = keys::generate_keypair().unwrap();
        let sk = keys::wif_to_private_key(&wif).unwrap();
        let digest = [0xab_u8; 32];
        let sig = keys::sign_digest(&sk, &digest).unwrap();
        // ECDSA signature is 64 bytes = 128 hex chars
        assert_eq!(sig.len(), 128, "Signature hex should be 128 chars, got {}", sig.len());
        // Should be valid hex
        assert!(hex::decode(&sig).is_ok());
    }

    #[test]
    fn different_digests_produce_different_signatures() {
        let (wif, _) = keys::generate_keypair().unwrap();
        let sk = keys::wif_to_private_key(&wif).unwrap();
        let sig1 = keys::sign_digest(&sk, &[0x01; 32]).unwrap();
        let sig2 = keys::sign_digest(&sk, &[0x02; 32]).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn multiple_keypairs_are_unique() {
        let (wif1, pub1) = keys::generate_keypair().unwrap();
        let (wif2, pub2) = keys::generate_keypair().unwrap();
        assert_ne!(wif1, wif2);
        assert_ne!(pub1, pub2);
    }
}

// ============================================================================
// Wallet module tests
// ============================================================================

mod wallet_tests {
    use pulsevm_keosd::{keys, wallet::Wallet};

    use super::*;

    fn setup() -> (TempDir, String) {
        let dir = TempDir::new().unwrap();
        let password = "test_password_123".to_string();
        (dir, password)
    }

    #[test]
    fn create_wallet_succeeds() {
        let (dir, password) = setup();
        let wallet = Wallet::create("test", &password, dir.path()).unwrap();
        assert!(!wallet.is_locked());
        assert_eq!(wallet.name, "test");
        // Wallet file should exist on disk
        assert!(dir.path().join("test.wallet").exists());
    }

    #[test]
    fn create_wallet_writes_encrypted_file() {
        let (dir, password) = setup();
        let _wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let contents = std::fs::read_to_string(dir.path().join("test.wallet")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        // Should have cipher_keys field
        assert!(parsed.get("cipher_keys").is_some());
    }

    #[test]
    fn lock_and_unlock() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        assert!(!wallet.is_locked());

        wallet.lock();
        assert!(wallet.is_locked());

        wallet.unlock(&password).unwrap();
        assert!(!wallet.is_locked());
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        wallet.lock();
        let result = wallet.unlock("wrong_password");
        assert!(result.is_err());
        assert!(wallet.is_locked());
    }

    #[test]
    fn unlock_already_unlocked_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let result = wallet.unlock(&password);
        assert!(result.is_err()); // AlreadyUnlocked
    }

    #[test]
    fn import_key_succeeds() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let (wif, expected_pub) = keys::generate_keypair().unwrap();
        let pub_key = wallet.import_key(&wif).unwrap();
        assert_eq!(pub_key, expected_pub);
    }

    #[test]
    fn import_duplicate_key_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let (wif, _) = keys::generate_keypair().unwrap();
        wallet.import_key(&wif).unwrap();
        let result = wallet.import_key(&wif);
        assert!(result.is_err());
    }

    #[test]
    fn import_key_on_locked_wallet_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        wallet.lock();
        let (wif, _) = keys::generate_keypair().unwrap();
        let result = wallet.import_key(&wif);
        assert!(result.is_err());
    }

    #[test]
    fn create_key_succeeds() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let pub_key = wallet.create_key().unwrap();
        assert!(pub_key.starts_with("PUB_K1_"), "Public key should start with PUB_K1_: {}", pub_key);
    }

    #[test]
    fn create_key_on_locked_wallet_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        wallet.lock();
        assert!(wallet.create_key().is_err());
    }

    #[test]
    fn list_public_keys() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        assert_eq!(wallet.list_public_keys().unwrap().len(), 0);

        let (wif1, _) = keys::generate_keypair().unwrap();
        let (wif2, _) = keys::generate_keypair().unwrap();
        wallet.import_key(&wif1).unwrap();
        wallet.import_key(&wif2).unwrap();

        let pub_keys = wallet.list_public_keys().unwrap();
        assert_eq!(pub_keys.len(), 2);
    }

    #[test]
    fn list_public_keys_on_locked_wallet_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        wallet.lock();
        assert!(wallet.list_public_keys().is_err());
    }

    #[test]
    fn list_keys_with_correct_password() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        wallet.import_key(&wif).unwrap();

        let keys_map = wallet.list_keys(&password).unwrap();
        assert_eq!(keys_map.len(), 1);
        assert_eq!(keys_map.get(&pub_key).unwrap(), &wif);
    }

    #[test]
    fn list_keys_with_wrong_password_fails() {
        let (dir, password) = setup();
        let wallet = Wallet::create("test", &password, dir.path()).unwrap();
        assert!(wallet.list_keys("wrong").is_err());
    }

    #[test]
    fn remove_key_succeeds() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        wallet.import_key(&wif).unwrap();
        assert_eq!(wallet.list_public_keys().unwrap().len(), 1);

        wallet.remove_key(&password, &pub_key).unwrap();
        assert_eq!(wallet.list_public_keys().unwrap().len(), 0);
    }

    #[test]
    fn remove_key_with_wrong_password_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        wallet.import_key(&wif).unwrap();
        assert!(wallet.remove_key("wrong", &pub_key).is_err());
        // Key should still be there
        assert_eq!(wallet.list_public_keys().unwrap().len(), 1);
    }

    #[test]
    fn remove_nonexistent_key_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        assert!(wallet.remove_key(&password, "EOSnotarealkey").is_err());
    }

    #[test]
    fn sign_digest_with_known_key() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        wallet.import_key(&wif).unwrap();

        let digest = [0xde_u8; 32];
        let sig = wallet.try_sign_digest(&digest, &pub_key).unwrap();
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().len(), 128); // 64 bytes = 128 hex
    }

    #[test]
    fn sign_digest_with_unknown_key_returns_none() {
        let (dir, password) = setup();
        let wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let digest = [0xde_u8; 32];
        let sig = wallet.try_sign_digest(&digest, "EOSnothere").unwrap();
        assert!(sig.is_none());
    }

    #[test]
    fn sign_digest_on_locked_wallet_fails() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        wallet.lock();
        assert!(wallet.try_sign_digest(&[0; 32], "EOS...").is_err());
    }

    #[test]
    fn keys_persist_across_lock_unlock() {
        let (dir, password) = setup();
        let mut wallet = Wallet::create("test", &password, dir.path()).unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        wallet.import_key(&wif).unwrap();

        wallet.lock();
        wallet.unlock(&password).unwrap();

        let pub_keys = wallet.list_public_keys().unwrap();
        assert_eq!(pub_keys.len(), 1);
        assert_eq!(pub_keys[0], pub_key);
    }

    #[test]
    fn open_existing_wallet() {
        let (dir, password) = setup();
        // Create a wallet and add a key
        {
            let mut wallet = Wallet::create("persist", &password, dir.path()).unwrap();
            let (wif, _) = keys::generate_keypair().unwrap();
            wallet.import_key(&wif).unwrap();
        }

        // Open from disk (loads locked)
        let mut wallet = Wallet::open("persist", dir.path()).unwrap();
        assert!(wallet.is_locked());

        wallet.unlock(&password).unwrap();
        assert_eq!(wallet.list_public_keys().unwrap().len(), 1);
    }

    #[test]
    fn open_nonexistent_wallet_fails() {
        let dir = TempDir::new().unwrap();
        assert!(Wallet::open("doesnotexist", dir.path()).is_err());
    }
}

// ============================================================================
// WalletManager tests
// ============================================================================

mod manager_tests {
    use pulsevm_keosd::{keys, manager::WalletManager};

    use super::*;

    fn setup() -> (TempDir, WalletManager) {
        let dir = TempDir::new().unwrap();
        let mgr = WalletManager::new(dir.path().to_path_buf(), 900).unwrap();
        (dir, mgr)
    }

    #[test]
    fn create_wallet_returns_password() {
        let (_dir, mut mgr) = setup();
        let password = mgr.create("test").unwrap();
        assert!(password.starts_with("PW"), "Password should start with PW prefix");
        assert!(password.len() > 10, "Password should be reasonably long");
    }

    #[test]
    fn create_duplicate_wallet_fails() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        assert!(mgr.create("test").is_err());
    }

    #[test]
    fn list_wallets_shows_unlocked_marker() {
        let (_dir, mut mgr) = setup();
        mgr.create("mywallet").unwrap();
        let list = mgr.list_wallets();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], "mywallet *"); // newly created = unlocked
    }

    #[test]
    fn list_wallets_shows_locked_without_marker() {
        let (_dir, mut mgr) = setup();
        mgr.create("mywallet").unwrap();
        mgr.lock("mywallet").unwrap();
        let list = mgr.list_wallets();
        assert_eq!(list[0], "mywallet"); // no * = locked
    }

    #[test]
    fn lock_and_unlock_wallet() {
        let (_dir, mut mgr) = setup();
        let password = mgr.create("test").unwrap();

        mgr.lock("test").unwrap();
        assert_eq!(mgr.list_wallets()[0], "test");

        mgr.unlock("test", &password).unwrap();
        assert_eq!(mgr.list_wallets()[0], "test *");
    }

    #[test]
    fn lock_nonexistent_wallet_fails() {
        let (_dir, mut mgr) = setup();
        assert!(mgr.lock("nope").is_err());
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        mgr.lock("test").unwrap();
        assert!(mgr.unlock("test", "wrong_password").is_err());
    }

    #[test]
    fn lock_all_locks_everything() {
        let (_dir, mut mgr) = setup();
        mgr.create("w1").unwrap();
        mgr.create("w2").unwrap();
        mgr.lock_all().unwrap();
        let list = mgr.list_wallets();
        for entry in &list {
            assert!(!entry.ends_with(" *"), "Wallet should be locked: {}", entry);
        }
    }

    #[test]
    fn import_key_into_wallet() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        let (wif, _) = keys::generate_keypair().unwrap();
        mgr.import_key("test", &wif).unwrap();
    }

    #[test]
    fn import_key_into_nonexistent_wallet_fails() {
        let (_dir, mut mgr) = setup();
        let (wif, _) = keys::generate_keypair().unwrap();
        assert!(mgr.import_key("nope", &wif).is_err());
    }

    #[test]
    fn import_key_into_locked_wallet_fails() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        mgr.lock("test").unwrap();
        let (wif, _) = keys::generate_keypair().unwrap();
        assert!(mgr.import_key("test", &wif).is_err());
    }

    #[test]
    fn create_key_in_wallet() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        let pub_key = mgr.create_key("test").unwrap();
        assert!(pub_key.starts_with("PUB_K1_"), "Public key should start with PUB_K1_: {}", pub_key);
    }

    #[test]
    fn get_public_keys_from_unlocked_wallets() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        let (wif1, pub1) = keys::generate_keypair().unwrap();
        let (wif2, pub2) = keys::generate_keypair().unwrap();
        mgr.import_key("test", &wif1).unwrap();
        mgr.import_key("test", &wif2).unwrap();

        let pub_keys = mgr.get_public_keys().unwrap();
        assert_eq!(pub_keys.len(), 2);
        assert!(pub_keys.contains(&pub1));
        assert!(pub_keys.contains(&pub2));
    }

    #[test]
    fn get_public_keys_fails_when_all_locked() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        mgr.lock("test").unwrap();
        assert!(mgr.get_public_keys().is_err());
    }

    #[test]
    fn get_public_keys_across_multiple_wallets() {
        let (_dir, mut mgr) = setup();
        let (wif1, pub1) = keys::generate_keypair().unwrap();
        let (wif2, pub2) = keys::generate_keypair().unwrap();
        mgr.create("w1").unwrap();
        mgr.create("w2").unwrap();
        mgr.import_key("w1", &wif1).unwrap();
        mgr.import_key("w2", &wif2).unwrap();

        let all = mgr.get_public_keys().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&pub1));
        assert!(all.contains(&pub2));
    }

    #[test]
    fn list_keys_requires_correct_password() {
        let (_dir, mut mgr) = setup();
        let password = mgr.create("test").unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        mgr.import_key("test", &wif).unwrap();

        let keys_map = mgr.list_keys("test", &password).unwrap();
        assert_eq!(keys_map.len(), 1);
        assert_eq!(keys_map.get(&pub_key).unwrap(), &wif);

        assert!(mgr.list_keys("test", "wrong").is_err());
    }

    #[test]
    fn remove_key_from_wallet() {
        let (_dir, mut mgr) = setup();
        let password = mgr.create("test").unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        mgr.import_key("test", &wif).unwrap();

        mgr.remove_key("test", &password, &pub_key).unwrap();
        let pub_keys = mgr.get_public_keys().unwrap();
        assert_eq!(pub_keys.len(), 0);
    }

    #[test]
    fn sign_digest_succeeds() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        mgr.import_key("test", &wif).unwrap();

        let digest = [0xca_u8; 32];
        let sigs = mgr.sign_digest(&digest, &[pub_key.clone()]).unwrap();
        assert_eq!(sigs.len(), 1);
        assert!(sigs.contains_key(&pub_key));
        assert_eq!(sigs[&pub_key].len(), 128); // 64 bytes hex
    }

    #[test]
    fn sign_digest_with_missing_key_fails() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        let digest = [0xca_u8; 32];
        let result = mgr.sign_digest(&digest, &["EOSnonexistent".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn sign_digest_with_multiple_keys() {
        let (_dir, mut mgr) = setup();
        mgr.create("test").unwrap();
        let (wif1, pub1) = keys::generate_keypair().unwrap();
        let (wif2, pub2) = keys::generate_keypair().unwrap();
        mgr.import_key("test", &wif1).unwrap();
        mgr.import_key("test", &wif2).unwrap();

        let digest = [0xfe_u8; 32];
        let sigs = mgr.sign_digest(&digest, &[pub1.clone(), pub2.clone()]).unwrap();
        assert_eq!(sigs.len(), 2);
        assert!(sigs.contains_key(&pub1));
        assert!(sigs.contains_key(&pub2));
        // Different keys should produce different signatures
        assert_ne!(sigs[&pub1], sigs[&pub2]);
    }

    #[test]
    fn set_timeout() {
        let (_dir, mut mgr) = setup();
        // Just verify it doesn't panic
        mgr.set_timeout(0);
        mgr.set_timeout(3600);
        mgr.set_timeout(900);
    }

    #[test]
    fn open_wallet_from_disk() {
        let (dir, mut mgr) = setup();
        let password = mgr.create("disktest").unwrap();
        let (wif, pub_key) = keys::generate_keypair().unwrap();
        mgr.import_key("disktest", &wif).unwrap();
        mgr.lock("disktest").unwrap();

        // Create a fresh manager pointing at same directory
        let mut mgr2 = WalletManager::new(dir.path().to_path_buf(), 900).unwrap();
        mgr2.open("disktest").unwrap();
        mgr2.unlock("disktest", &password).unwrap();

        let pub_keys = mgr2.get_public_keys().unwrap();
        assert_eq!(pub_keys.len(), 1);
        assert_eq!(pub_keys[0], pub_key);
    }
}

// ============================================================================
// HTTP API integration tests
// ============================================================================

mod api_tests {
    use super::*;
    use actix_web::{http::StatusCode, test};
    use pulsevm_keosd::{api, keys, manager::WalletManager};
    use std::sync::Mutex;

    /// Helper: create an actix-web test app with a fresh WalletManager.
    async fn test_app() -> (
        TempDir,
        impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >,
    ) {
        let dir = TempDir::new().unwrap();
        let mgr = WalletManager::new(dir.path().to_path_buf(), 900).unwrap();
        let state = web::Data::new(api::AppState {
            manager: Mutex::new(mgr),
        });

        let app = test::init_service(
            App::new()
                .app_data(state)
                .configure(api::configure_routes),
        )
        .await;

        (dir, app)
    }

    #[actix_rt::test]
    async fn api_create_wallet() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("mywallet")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body: String = test::read_body_json(resp).await;
        assert!(body.starts_with("PW"), "Password should start with PW: {}", body);
    }

    #[actix_rt::test]
    async fn api_create_duplicate_wallet_fails() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("dup")
            .to_request();
        test::call_service(&app, req).await;

        let req2 = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("dup")
            .to_request();
        let resp = test::call_service(&app, req2).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], 3120001);
    }

    #[actix_rt::test]
    async fn api_list_wallets() {
        let (_dir, app) = test_app().await;

        // Create a wallet
        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("alpha")
            .to_request();
        test::call_service(&app, req).await;

        // List via POST
        let req = test::TestRequest::post()
            .uri("/v1/wallet/list_wallets")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Vec<String> = test::read_body_json(resp).await;
        assert_eq!(body.len(), 1);
        assert_eq!(body[0], "alpha *");

        // Also works via GET
        let req = test::TestRequest::get()
            .uri("/v1/wallet/list_wallets")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn api_lock_and_unlock() {
        let (_dir, app) = test_app().await;

        // Create
        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("locktest")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let password: String = test::read_body_json(resp).await;

        // Lock
        let req = test::TestRequest::post()
            .uri("/v1/wallet/lock")
            .set_json("locktest")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify locked
        let req = test::TestRequest::post()
            .uri("/v1/wallet/list_wallets")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let list: Vec<String> = test::read_body_json(resp).await;
        assert_eq!(list[0], "locktest");

        // Unlock
        let req = test::TestRequest::post()
            .uri("/v1/wallet/unlock")
            .set_json(vec!["locktest", &password])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify unlocked
        let req = test::TestRequest::post()
            .uri("/v1/wallet/list_wallets")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let list: Vec<String> = test::read_body_json(resp).await;
        assert_eq!(list[0], "locktest *");
    }

    #[actix_rt::test]
    async fn api_unlock_wrong_password() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("badpw")
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/lock")
            .set_json("badpw")
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/unlock")
            .set_json(vec!["badpw", "wrong_password"])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], 3120005);
    }

    #[actix_rt::test]
    async fn api_lock_all() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("a")
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("b")
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/lock_all")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/v1/wallet/list_wallets")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let list: Vec<String> = test::read_body_json(resp).await;
        for w in &list {
            assert!(!w.ends_with(" *"), "All wallets should be locked: {}", w);
        }
    }

    #[actix_rt::test]
    async fn api_create_key() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("keytest")
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create_key")
            .set_json(vec!["keytest", "K1"])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let pub_key: String = test::read_body_json(resp).await;
        assert!(pub_key.starts_with("PUB_K1_"), "Public key should start with PUB_K1_: {}", pub_key);
    }

    #[actix_rt::test]
    async fn api_import_key() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("imptest")
            .to_request();
        test::call_service(&app, req).await;

        let (wif, _) = keys::generate_keypair().unwrap();
        let req = test::TestRequest::post()
            .uri("/v1/wallet/import_key")
            .set_json(vec!["imptest", &wif])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[actix_rt::test]
    async fn api_get_public_keys() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("pubkeys")
            .to_request();
        test::call_service(&app, req).await;

        let (wif, expected_pub) = keys::generate_keypair().unwrap();
        let req = test::TestRequest::post()
            .uri("/v1/wallet/import_key")
            .set_json(vec!["pubkeys", &wif])
            .to_request();
        test::call_service(&app, req).await;

        // POST
        let req = test::TestRequest::post()
            .uri("/v1/wallet/get_public_keys")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let pub_keys: Vec<String> = test::read_body_json(resp).await;
        assert_eq!(pub_keys.len(), 1);
        assert_eq!(pub_keys[0], expected_pub);

        // GET variant
        let req = test::TestRequest::get()
            .uri("/v1/wallet/get_public_keys")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn api_get_public_keys_all_locked_fails() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("locked")
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/lock")
            .set_json("locked")
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/get_public_keys")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], 3120003);
    }

    #[actix_rt::test]
    async fn api_list_keys() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("listkeys")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let password: String = test::read_body_json(resp).await;

        let (wif, expected_pub) = keys::generate_keypair().unwrap();
        let req = test::TestRequest::post()
            .uri("/v1/wallet/import_key")
            .set_json(vec!["listkeys", &wif])
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/list_keys")
            .set_json(vec!["listkeys", &password])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let pairs: Vec<Vec<String>> = test::read_body_json(resp).await;
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0][0], expected_pub);
        assert_eq!(pairs[0][1], wif);
    }

    #[actix_rt::test]
    async fn api_remove_key() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("rmkey")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let password: String = test::read_body_json(resp).await;

        let (wif, pub_key) = keys::generate_keypair().unwrap();
        let req = test::TestRequest::post()
            .uri("/v1/wallet/import_key")
            .set_json(vec!["rmkey", &wif])
            .to_request();
        test::call_service(&app, req).await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/remove_key")
            .set_json(vec!["rmkey", &password, &pub_key])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify key is gone
        let req = test::TestRequest::post()
            .uri("/v1/wallet/get_public_keys")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let keys: Vec<String> = test::read_body_json(resp).await;
        assert_eq!(keys.len(), 0);
    }

    #[actix_rt::test]
    async fn api_set_timeout() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/set_timeout")
            .set_json(300_u64)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn api_sign_digest() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("signtest")
            .to_request();
        test::call_service(&app, req).await;

        let (wif, pub_key) = keys::generate_keypair().unwrap();
        let req = test::TestRequest::post()
            .uri("/v1/wallet/import_key")
            .set_json(vec!["signtest", &wif])
            .to_request();
        test::call_service(&app, req).await;

        let digest_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let req = test::TestRequest::post()
            .uri("/v1/wallet/sign_digest")
            .set_json((digest_hex, &pub_key))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let sig: String = test::read_body_json(resp).await;
        assert_eq!(sig.len(), 128);
        assert!(hex::decode(&sig).is_ok());
    }

    #[actix_rt::test]
    async fn api_sign_digest_missing_key_fails() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("sigfail")
            .to_request();
        test::call_service(&app, req).await;

        let digest_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let req = test::TestRequest::post()
            .uri("/v1/wallet/sign_digest")
            .set_json((digest_hex, "EOSnonexistent"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], 3120004);
    }

    #[actix_rt::test]
    async fn api_sign_transaction() {
        let (_dir, app) = test_app().await;

        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("txsign")
            .to_request();
        test::call_service(&app, req).await;

        let (wif, pub_key) = keys::generate_keypair().unwrap();
        let req = test::TestRequest::post()
            .uri("/v1/wallet/import_key")
            .set_json(vec!["txsign", &wif])
            .to_request();
        test::call_service(&app, req).await;

        let chain_id = "0000000000000000000000000000000000000000000000000000000000000000";
        let tx = serde_json::json!({
            "expiration": "2025-01-01T00:00:00",
            "ref_block_num": 0,
            "ref_block_prefix": 0,
            "actions": []
        });
        let req = test::TestRequest::post()
            .uri("/v1/wallet/sign_transaction")
            .set_json((tx, vec![&pub_key], chain_id))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        // Should have signatures array added
        assert!(body.get("signatures").is_some());
        let sigs = body["signatures"].as_array().unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[actix_rt::test]
    async fn api_open_wallet() {
        let (_dir, app) = test_app().await;

        // Create a wallet first (so the file exists)
        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("openme")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let _password: String = test::read_body_json(resp).await;

        // Open should succeed (already open, idempotent)
        let req = test::TestRequest::post()
            .uri("/v1/wallet/open")
            .set_json("openme")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn api_full_workflow() {
        let (_dir, app) = test_app().await;

        // 1. Create wallet
        let req = test::TestRequest::post()
            .uri("/v1/wallet/create")
            .set_json("workflow")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let password: String = test::read_body_json(resp).await;

        // 2. Create a key
        let req = test::TestRequest::post()
            .uri("/v1/wallet/create_key")
            .set_json(vec!["workflow", "K1"])
            .to_request();
        let resp = test::call_service(&app, req).await;
        let created_key: String = test::read_body_json(resp).await;

        // 3. Import another key
        let (wif, imported_key) = keys::generate_keypair().unwrap();
        let req = test::TestRequest::post()
            .uri("/v1/wallet/import_key")
            .set_json(vec!["workflow", &wif])
            .to_request();
        test::call_service(&app, req).await;

        // 4. List public keys - should have 2
        let req = test::TestRequest::post()
            .uri("/v1/wallet/get_public_keys")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let all_keys: Vec<String> = test::read_body_json(resp).await;
        assert_eq!(all_keys.len(), 2);

        // 5. Lock
        let req = test::TestRequest::post()
            .uri("/v1/wallet/lock")
            .set_json("workflow")
            .to_request();
        test::call_service(&app, req).await;

        // 6. Signing should fail while locked
        let digest = "ff".repeat(32);
        let req = test::TestRequest::post()
            .uri("/v1/wallet/sign_digest")
            .set_json((&digest, &created_key))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // 7. Unlock
        let req = test::TestRequest::post()
            .uri("/v1/wallet/unlock")
            .set_json(vec!["workflow", &password])
            .to_request();
        test::call_service(&app, req).await;

        // 8. Sign should succeed now
        let req = test::TestRequest::post()
            .uri("/v1/wallet/sign_digest")
            .set_json((&digest, &created_key))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // 9. Remove the imported key
        let req = test::TestRequest::post()
            .uri("/v1/wallet/remove_key")
            .set_json(vec!["workflow", &password, &imported_key])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // 10. Should only have 1 key left
        let req = test::TestRequest::post()
            .uri("/v1/wallet/get_public_keys")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let remaining: Vec<String> = test::read_body_json(resp).await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], created_key);
    }
}