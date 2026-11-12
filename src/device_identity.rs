//! Device identity backed by the operating system's credential store.
//!
//! The private signing key is only persisted through the OS credential store.
//! This module never writes it to an ordinary file or database.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use keyring::{Entry, Error as KeyringError};
use rand_core::{OsRng, RngCore};
use uuid::{Builder as UuidBuilder, Uuid};
use zeroize::Zeroizing;

use crate::error::ShieldError;

const CREDENTIAL_SERVICE: &str = "daemonone-shield";
const CREDENTIAL_USER: &str = "device-identity-v1";
const BUNDLE_VERSION: u8 = 1;
const BUNDLE_LEN: usize = 1 + 16 + 32;

/// A device identifier and Ed25519 signing key.
///
/// The signing key is private to this type. Use [`DeviceIdentity::public_key_export`]
/// to obtain public enrollment data; formatting this value never prints the
/// private key.
pub struct DeviceIdentity {
    device_id: Uuid,
    signing_key: SigningKey,
}

impl DeviceIdentity {
    /// Creates a new identity and stores its private key in the OS credential
    /// store. It fails if an identity already exists or secure storage cannot
    /// be accessed.
    pub fn create() -> Result<Self, ShieldError> {
        let store = OsCredentialStore::new()?;
        Self::create_with_store(&store)
    }

    /// Loads the saved identity from the OS credential store.
    pub fn load() -> Result<Self, ShieldError> {
        let store = OsCredentialStore::new()?;
        Self::load_with_store(&store)
    }

    /// Returns the random UUID assigned to this device.
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// Returns the Ed25519 public key as 32 bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns an enrollment string containing only the algorithm and public
    /// key, encoded as lowercase hexadecimal.
    pub fn public_key_export(&self) -> String {
        format!("ed25519:{}", encode_hex(&self.public_key_bytes()))
    }

    pub(crate) fn sign_bytes(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    fn create_with_store(store: &impl CredentialStore) -> Result<Self, ShieldError> {
        let existing_secret = store.read_secret()?.map(Zeroizing::new);
        if existing_secret.is_some() {
            return Err(ShieldError::new(
                "A Shield device identity already exists in the OS credential store.",
            ));
        }

        let identity = Self::generate()?;
        let bundle = identity.encode_bundle();
        store.write_secret(&bundle)?;
        Ok(identity)
    }

    fn load_with_store(store: &impl CredentialStore) -> Result<Self, ShieldError> {
        let secret = store
            .read_secret()?
            .ok_or_else(|| ShieldError::new("No saved Shield device identity was found."))?;
        Self::decode_bundle(secret)
    }

    pub(crate) fn generate() -> Result<Self, ShieldError> {
        let mut random_bytes = Zeroizing::new([0_u8; 48]);
        OsRng.try_fill_bytes(&mut *random_bytes).map_err(|_| {
            ShieldError::new("The operating system random number generator failed.")
        })?;

        let mut private_bytes = Zeroizing::new([0_u8; 32]);
        private_bytes.copy_from_slice(&random_bytes[..32]);
        let mut id_bytes = [0_u8; 16];
        id_bytes.copy_from_slice(&random_bytes[32..]);

        let signing_key = SigningKey::from_bytes(&private_bytes);
        Ok(Self {
            device_id: UuidBuilder::from_random_bytes(id_bytes).into_uuid(),
            signing_key,
        })
    }

    fn encode_bundle(&self) -> Zeroizing<Vec<u8>> {
        let mut bundle = Zeroizing::new(Vec::with_capacity(BUNDLE_LEN));
        bundle.push(BUNDLE_VERSION);
        bundle.extend_from_slice(self.device_id.as_bytes());

        let private_bytes = Zeroizing::new(self.signing_key.to_bytes());
        bundle.extend_from_slice(&*private_bytes);
        bundle
    }

    fn decode_bundle(bundle: Vec<u8>) -> Result<Self, ShieldError> {
        let bundle = Zeroizing::new(bundle);
        if bundle.len() != BUNDLE_LEN || bundle[0] != BUNDLE_VERSION {
            return Err(ShieldError::new(
                "The saved Shield identity has an unsupported or invalid format.",
            ));
        }

        let mut id_bytes = [0_u8; 16];
        id_bytes.copy_from_slice(&bundle[1..17]);

        let mut private_bytes = Zeroizing::new([0_u8; 32]);
        private_bytes.copy_from_slice(&bundle[17..]);

        Ok(Self {
            device_id: Uuid::from_bytes(id_bytes),
            signing_key: SigningKey::from_bytes(&private_bytes),
        })
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .field("public_key", &self.public_key_export())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Device ID: {}\nPublic key: {}",
            self.device_id,
            self.public_key_export()
        )
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

trait CredentialStore {
    fn read_secret(&self) -> Result<Option<Vec<u8>>, ShieldError>;
    fn write_secret(&self, secret: &[u8]) -> Result<(), ShieldError>;
}

struct OsCredentialStore {
    entry: Entry,
}

impl OsCredentialStore {
    fn new() -> Result<Self, ShieldError> {
        let entry =
            Entry::new(CREDENTIAL_SERVICE, CREDENTIAL_USER).map_err(|_| secure_storage_error())?;
        Ok(Self { entry })
    }
}

impl CredentialStore for OsCredentialStore {
    fn read_secret(&self) -> Result<Option<Vec<u8>>, ShieldError> {
        match self.entry.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(_) => Err(secure_storage_error()),
        }
    }

    fn write_secret(&self, secret: &[u8]) -> Result<(), ShieldError> {
        self.entry
            .set_secret(secret)
            .map_err(|_| secure_storage_error())
    }
}

fn secure_storage_error() -> ShieldError {
    ShieldError::new(
        "The OS credential store is unavailable. Shield did not save the private key to a file.",
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::{encode_hex, secure_storage_error, CredentialStore, DeviceIdentity};
    use crate::error::ShieldError;

    #[derive(Default)]
    struct MemoryStore(RefCell<Option<Vec<u8>>>);

    impl CredentialStore for MemoryStore {
        fn read_secret(&self) -> Result<Option<Vec<u8>>, ShieldError> {
            Ok(self.0.borrow().clone())
        }

        fn write_secret(&self, secret: &[u8]) -> Result<(), ShieldError> {
            *self.0.borrow_mut() = Some(secret.to_vec());
            Ok(())
        }
    }

    struct UnavailableStore;

    impl CredentialStore for UnavailableStore {
        fn read_secret(&self) -> Result<Option<Vec<u8>>, ShieldError> {
            Err(secure_storage_error())
        }

        fn write_secret(&self, _secret: &[u8]) -> Result<(), ShieldError> {
            Err(secure_storage_error())
        }
    }

    #[test]
    fn generated_identities_have_unique_ids_and_public_keys() {
        let first = DeviceIdentity::generate().expect("OS randomness should be available");
        let second = DeviceIdentity::generate().expect("OS randomness should be available");

        assert_ne!(first.device_id(), second.device_id());
        assert_ne!(first.public_key_bytes(), second.public_key_bytes());
        assert_eq!(first.device_id().get_version(), Some(uuid::Version::Random));
        assert_eq!(first.device_id().get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn public_key_export_contains_only_the_public_key() {
        let identity = DeviceIdentity::generate().expect("OS randomness should be available");
        let exported = identity.public_key_export();

        assert!(exported.starts_with("ed25519:"));
        assert_eq!(
            exported,
            format!("ed25519:{}", encode_hex(&identity.public_key_bytes()))
        );
        assert_eq!(exported.len(), "ed25519:".len() + 64);
    }

    #[test]
    fn debug_output_does_not_contain_private_key_bytes() {
        let identity = DeviceIdentity::generate().expect("OS randomness should be available");
        let private_bytes = identity.signing_key.to_bytes();
        let debug_output = format!("{identity:?}");

        assert!(!debug_output.contains(&encode_hex(&private_bytes)));
        assert!(debug_output.contains(&identity.device_id().to_string()));
        assert!(debug_output.contains(&identity.public_key_export()));
    }

    #[test]
    fn identity_can_be_loaded_from_credential_storage() {
        let store = MemoryStore::default();
        let created = DeviceIdentity::create_with_store(&store).expect("create identity");
        let loaded = DeviceIdentity::load_with_store(&store).expect("load identity");

        assert_eq!(loaded.device_id(), created.device_id());
        assert_eq!(loaded.public_key_bytes(), created.public_key_bytes());
    }

    #[test]
    fn unavailable_credential_storage_fails_closed() {
        let error = DeviceIdentity::create_with_store(&UnavailableStore)
            .expect_err("creation must fail when secure storage is unavailable");

        assert!(error
            .to_string()
            .contains("OS credential store is unavailable"));
        assert!(error
            .to_string()
            .contains("did not save the private key to a file"));
    }
}
