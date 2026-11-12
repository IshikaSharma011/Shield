//! Versioned, deterministic security request encoding and Ed25519 signatures.

use std::{
    collections::BTreeMap,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use uuid::{Builder as UuidBuilder, Uuid};
use zeroize::Zeroizing;

use crate::device_identity::DeviceIdentity;

const FORMAT_MAGIC: &[u8; 4] = b"SHLD";
const FORMAT_VERSION: u8 = 1;
const MAX_REQUEST_SIZE: usize = 1_048_576;
const MAX_PARAMETERS: usize = 128;
const MAX_TEXT_BYTES: usize = 4096;
const NONCE_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

/// One task request. The parameter map sorts keys so the same data always has
/// one serialized representation.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRequest {
    pub device_id: Uuid,
    pub request_id: Uuid,
    pub task_id: String,
    pub parameters: BTreeMap<String, String>,
    /// Unix time in milliseconds.
    pub timestamp: u64,
    /// A 32-byte random value included in the signed request.
    pub nonce: [u8; NONCE_LEN],
}

impl TaskRequest {
    /// Creates a request with a random request ID and nonce and the current
    /// Unix timestamp in milliseconds.
    pub fn new(
        device_id: Uuid,
        task_id: impl Into<String>,
        parameters: BTreeMap<String, String>,
    ) -> Result<Self, SignatureError> {
        let mut random_bytes = Zeroizing::new([0_u8; 16 + NONCE_LEN]);
        OsRng
            .try_fill_bytes(&mut *random_bytes)
            .map_err(|_| SignatureError::RandomnessUnavailable)?;

        let mut request_id_bytes = [0_u8; 16];
        request_id_bytes.copy_from_slice(&random_bytes[..16]);
        let request_id = UuidBuilder::from_random_bytes(request_id_bytes).into_uuid();

        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&random_bytes[16..]);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SignatureError::ClockUnavailable)?
            .as_millis()
            .try_into()
            .map_err(|_| SignatureError::ClockUnavailable)?;

        let request = Self {
            device_id,
            request_id,
            task_id: task_id.into(),
            parameters,
            timestamp,
            nonce,
        };
        request.serialize()?;
        Ok(request)
    }

    /// Serializes all security-relevant fields to the Shield request format.
    /// Integers use big-endian byte order; parameters are written in sorted
    /// key order because they are stored in a `BTreeMap`.
    pub fn serialize(&self) -> Result<Vec<u8>, SignatureError> {
        validate_text("task_id", &self.task_id, false)?;
        if self.parameters.len() > MAX_PARAMETERS {
            return Err(SignatureError::MalformedRequest(
                "the request has too many parameters",
            ));
        }

        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(FORMAT_MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(self.device_id.as_bytes());
        bytes.extend_from_slice(self.request_id.as_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        write_text(&mut bytes, &self.task_id)?;
        bytes.extend_from_slice(&(self.parameters.len() as u16).to_be_bytes());

        for (key, value) in &self.parameters {
            validate_text("parameter key", key, false)?;
            validate_text("parameter value", value, true)?;
            write_text(&mut bytes, key)?;
            write_text(&mut bytes, value)?;
            if bytes.len() > MAX_REQUEST_SIZE {
                return Err(SignatureError::MalformedRequest(
                    "the serialized request exceeds the size limit",
                ));
            }
        }

        if bytes.len() > MAX_REQUEST_SIZE {
            return Err(SignatureError::MalformedRequest(
                "the serialized request exceeds the size limit",
            ));
        }
        Ok(bytes)
    }

    /// Parses and validates a serialized request, rejecting unknown versions,
    /// invalid UTF-8, unsorted or duplicate parameters, and trailing bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() > MAX_REQUEST_SIZE {
            return Err(SignatureError::MalformedRequest(
                "the serialized request exceeds the size limit",
            ));
        }

        let mut reader = Reader::new(bytes);
        if reader.read_exact(FORMAT_MAGIC.len())? != FORMAT_MAGIC {
            return Err(SignatureError::MalformedRequest(
                "the request format marker is invalid",
            ));
        }
        let version = reader.read_u8()?;
        if version != FORMAT_VERSION {
            return Err(SignatureError::MalformedRequest(
                "the request protocol version is unsupported",
            ));
        }

        let device_id = Uuid::from_bytes(reader.read_array::<16>()?);
        let request_id = Uuid::from_bytes(reader.read_array::<16>()?);
        let timestamp = reader.read_u64()?;
        let nonce = reader.read_array::<NONCE_LEN>()?;
        let task_id = reader.read_text("task_id", false)?;
        let parameter_count = usize::from(reader.read_u16()?);
        if parameter_count > MAX_PARAMETERS {
            return Err(SignatureError::MalformedRequest(
                "the request has too many parameters",
            ));
        }

        let mut parameters = BTreeMap::new();
        let mut previous_key: Option<String> = None;
        for _ in 0..parameter_count {
            let key = reader.read_text("parameter key", false)?;
            let value = reader.read_text("parameter value", true)?;
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err(SignatureError::MalformedRequest(
                    "parameter keys are not in canonical order",
                ));
            }
            previous_key = Some(key.clone());
            parameters.insert(key, value);
        }

        if !reader.is_finished() {
            return Err(SignatureError::MalformedRequest(
                "the request contains trailing bytes",
            ));
        }

        let request = Self {
            device_id,
            request_id,
            task_id,
            parameters,
            timestamp,
            nonce,
        };
        if request.serialize()?.as_slice() != bytes {
            return Err(SignatureError::MalformedRequest(
                "the request is not in canonical form",
            ));
        }
        Ok(request)
    }
}

impl fmt::Debug for TaskRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskRequest")
            .field("device_id", &self.device_id)
            .field("request_id", &self.request_id)
            .field("task_id", &"[redacted]")
            .field("parameter_count", &self.parameters.len())
            .field("timestamp", &self.timestamp)
            .field("nonce", &"[redacted]")
            .finish()
    }
}

/// A serialized request and its signature kept as distinct values.
pub struct SignedRequest {
    request_bytes: Vec<u8>,
    signature: [u8; SIGNATURE_LEN],
}

impl SignedRequest {
    /// Reconstructs a signed request from detached request and signature
    /// fields, as a transport or storage adapter would do. Verification is
    /// still required before trusting either field.
    pub fn from_parts(
        request_bytes: Vec<u8>,
        signature_bytes: &[u8],
    ) -> Result<Self, SignatureError> {
        if signature_bytes.len() != SIGNATURE_LEN {
            return Err(SignatureError::MalformedSignature);
        }
        let mut signature = [0_u8; SIGNATURE_LEN];
        signature.copy_from_slice(signature_bytes);
        Ok(Self {
            request_bytes,
            signature,
        })
    }

    /// Returns the exact request bytes that were signed.
    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    /// Returns the detached 64-byte Ed25519 signature.
    pub fn signature_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Verifies this signed request against the key registered for a device.
    pub fn verify(
        &self,
        registered_device_id: Uuid,
        registered_public_key: &VerifyingKey,
    ) -> Result<TaskRequest, SignatureError> {
        verify_request(
            &self.request_bytes,
            &self.signature,
            registered_device_id,
            registered_public_key,
        )
    }
}

impl fmt::Debug for SignedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedRequest")
            .field("request_bytes_len", &self.request_bytes.len())
            .field("signature_len", &self.signature.len())
            .finish_non_exhaustive()
    }
}

/// Serializes and signs every request field using the sender identity.
pub fn sign_request(
    request: &TaskRequest,
    identity: &DeviceIdentity,
) -> Result<SignedRequest, SignatureError> {
    if request.device_id != identity.device_id() {
        return Err(SignatureError::SignerDeviceMismatch);
    }
    let request_bytes = request.serialize()?;
    let signature = identity.sign_bytes(&request_bytes);
    Ok(SignedRequest {
        request_bytes,
        signature,
    })
}

/// Validates and verifies exact request bytes against the public key registered
/// for `registered_device_id`. The public key is supplied by the caller's
/// trusted registry; it is never read from the request.
pub fn verify_request(
    request_bytes: &[u8],
    signature_bytes: &[u8],
    registered_device_id: Uuid,
    registered_public_key: &VerifyingKey,
) -> Result<TaskRequest, SignatureError> {
    let request = TaskRequest::deserialize(request_bytes)?;
    if request.device_id != registered_device_id {
        return Err(SignatureError::RegisteredDeviceMismatch);
    }
    if signature_bytes.len() != SIGNATURE_LEN {
        return Err(SignatureError::MalformedSignature);
    }

    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| SignatureError::MalformedSignature)?;
    registered_public_key
        .verify_strict(request_bytes, &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    Ok(request)
}

fn validate_text(field: &'static str, text: &str, allow_empty: bool) -> Result<(), SignatureError> {
    if !allow_empty && text.is_empty() {
        return Err(SignatureError::MalformedRequest(match field {
            "task_id" => "task_id cannot be empty",
            "parameter key" => "parameter keys cannot be empty",
            _ => "a required text field cannot be empty",
        }));
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(SignatureError::MalformedRequest(match field {
            "task_id" => "task_id exceeds the size limit",
            "parameter key" => "a parameter key exceeds the size limit",
            _ => "a parameter value exceeds the size limit",
        }));
    }
    Ok(())
}

fn write_text(bytes: &mut Vec<u8>, text: &str) -> Result<(), SignatureError> {
    let length = u16::try_from(text.len())
        .map_err(|_| SignatureError::MalformedRequest("a text field exceeds the encoding limit"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(text.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], SignatureError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SignatureError::MalformedRequest(
                "the request length is invalid",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SignatureError::MalformedRequest(
                "the request ended unexpectedly",
            ))?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], SignatureError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| SignatureError::MalformedRequest("a fixed-size field is incomplete"))
    }

    fn read_u8(&mut self) -> Result<u8, SignatureError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, SignatureError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, SignatureError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_text(
        &mut self,
        field: &'static str,
        allow_empty: bool,
    ) -> Result<String, SignatureError> {
        let length = usize::from(self.read_u16()?);
        if length > MAX_TEXT_BYTES {
            return Err(SignatureError::MalformedRequest(match field {
                "task_id" => "task_id exceeds the size limit",
                "parameter key" => "a parameter key exceeds the size limit",
                _ => "a parameter value exceeds the size limit",
            }));
        }
        let text = std::str::from_utf8(self.read_exact(length)?)
            .map_err(|_| SignatureError::MalformedRequest("a text field is not valid UTF-8"))?
            .to_owned();
        validate_text(field, &text, allow_empty)?;
        Ok(text)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Errors that distinguish malformed input from failed signature checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    MalformedRequest(&'static str),
    MalformedSignature,
    InvalidSignature,
    RegisteredDeviceMismatch,
    SignerDeviceMismatch,
    RandomnessUnavailable,
    ClockUnavailable,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRequest(reason) => write!(formatter, "Malformed request: {reason}."),
            Self::MalformedSignature => formatter
                .write_str("Malformed signature: an Ed25519 signature must be exactly 64 bytes."),
            Self::InvalidSignature => {
                formatter.write_str("Invalid signature: verification failed.")
            }
            Self::RegisteredDeviceMismatch => formatter.write_str(
                "Request device ID does not match the device registered for this public key.",
            ),
            Self::SignerDeviceMismatch => formatter
                .write_str("Request device ID does not match the identity used to sign it."),
            Self::RandomnessUnavailable => {
                formatter.write_str("The operating system random number generator failed.")
            }
            Self::ClockUnavailable => {
                formatter.write_str("The system clock could not provide a valid timestamp.")
            }
        }
    }
}

impl std::error::Error for SignatureError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::VerifyingKey;
    use uuid::Uuid;

    use super::{sign_request, verify_request, SignatureError, SignedRequest, TaskRequest};
    use crate::device_identity::DeviceIdentity;

    fn sample_request(device_id: Uuid) -> TaskRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert("mode".to_owned(), "safe".to_owned());
        parameters.insert("target".to_owned(), "node-7".to_owned());
        TaskRequest::new(device_id, "status.report", parameters).expect("create task request")
    }

    fn identity_and_request() -> (DeviceIdentity, TaskRequest) {
        let identity = DeviceIdentity::generate().expect("generate device identity");
        let request = sample_request(identity.device_id());
        (identity, request)
    }

    #[test]
    fn valid_signature_passes_and_returns_the_request() {
        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let registered_key = VerifyingKey::from_bytes(&identity.public_key_bytes())
            .expect("registered public key is valid");

        let verified = signed
            .verify(identity.device_id(), &registered_key)
            .expect("signature should verify");

        assert_eq!(verified, request);
        assert_ne!(
            signed.request_bytes().as_ptr(),
            signed.signature_bytes().as_ptr()
        );
    }

    #[test]
    fn modified_request_bytes_fail_verification() {
        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let registered_key = VerifyingKey::from_bytes(&identity.public_key_bytes())
            .expect("registered public key is valid");
        let mut changed_bytes = signed.request_bytes().to_vec();
        let task_id_offset = 4 + 1 + 16 + 16 + 8 + 32 + 2;
        let task_id_first_byte = task_id_offset + 2;
        changed_bytes[task_id_first_byte] ^= 1;

        let result = verify_request(
            &changed_bytes,
            signed.signature_bytes(),
            identity.device_id(),
            &registered_key,
        );

        assert_eq!(result, Err(SignatureError::InvalidSignature));
    }

    #[test]
    fn every_security_relevant_request_field_is_signed() {
        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let registered_key = VerifyingKey::from_bytes(&identity.public_key_bytes())
            .expect("registered public key is valid");
        // Offsets cover device ID, request ID, timestamp, nonce, task ID, the
        // first parameter key, and its value in the documented v1 layout.
        for offset in [5, 21, 37, 45, 79, 96, 102] {
            let mut changed_bytes = signed.request_bytes().to_vec();
            changed_bytes[offset] ^= 1;
            let registered_id = if offset == 5 {
                Uuid::from_slice(&changed_bytes[5..21]).expect("valid UUID bytes")
            } else {
                identity.device_id()
            };

            assert_eq!(
                verify_request(
                    &changed_bytes,
                    signed.signature_bytes(),
                    registered_id,
                    &registered_key,
                ),
                Err(SignatureError::InvalidSignature),
                "byte at offset {offset} must be signature-bound"
            );
        }
    }

    #[test]
    fn incorrect_registered_public_key_fails_verification() {
        let (identity, request) = identity_and_request();
        let other_identity = DeviceIdentity::generate().expect("generate second identity");
        let signed = sign_request(&request, &identity).expect("sign request");
        let incorrect_key = VerifyingKey::from_bytes(&other_identity.public_key_bytes())
            .expect("registered public key is valid");

        assert_eq!(
            signed.verify(identity.device_id(), &incorrect_key),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn invalid_signature_fails_verification() {
        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let registered_key = VerifyingKey::from_bytes(&identity.public_key_bytes())
            .expect("registered public key is valid");
        let invalid_signature = [0_u8; 64];

        assert_eq!(
            verify_request(
                signed.request_bytes(),
                &invalid_signature,
                identity.device_id(),
                &registered_key,
            ),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn malformed_signature_length_is_rejected() {
        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let registered_key = VerifyingKey::from_bytes(&identity.public_key_bytes())
            .expect("registered public key is valid");

        assert_eq!(
            verify_request(
                signed.request_bytes(),
                &[0_u8; 63],
                identity.device_id(),
                &registered_key,
            ),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn malformed_request_is_rejected() {
        assert!(matches!(
            TaskRequest::deserialize(b"not a Shield request"),
            Err(SignatureError::MalformedRequest(_))
        ));

        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let registered_key = VerifyingKey::from_bytes(&identity.public_key_bytes())
            .expect("registered public key is valid");
        assert!(matches!(
            verify_request(
                &signed.request_bytes()[..10],
                signed.signature_bytes(),
                identity.device_id(),
                &registered_key,
            ),
            Err(SignatureError::MalformedRequest(_))
        ));
    }

    #[test]
    fn request_serialization_is_deterministic_and_versioned() {
        let (identity, request) = identity_and_request();
        let first = request.serialize().expect("serialize request");
        let second = request.serialize().expect("serialize request again");

        assert_eq!(first, second);
        assert_eq!(&first[..4], b"SHLD");
        assert_eq!(first[4], 1);
        assert_eq!(identity.device_id(), request.device_id);
        assert_eq!(TaskRequest::deserialize(&first), Ok(request));
    }

    #[test]
    fn request_device_id_must_match_registered_device() {
        let (identity, request) = identity_and_request();
        let other_identity = DeviceIdentity::generate().expect("generate second identity");
        let signed = sign_request(&request, &identity).expect("sign request");
        let registered_key = VerifyingKey::from_bytes(&identity.public_key_bytes())
            .expect("registered public key is valid");

        assert_eq!(
            signed.verify(other_identity.device_id(), &registered_key),
            Err(SignatureError::RegisteredDeviceMismatch)
        );
    }

    #[test]
    fn signing_rejects_a_request_for_another_device() {
        let identity = DeviceIdentity::generate().expect("generate device identity");
        let other_device_id = uuid::Builder::from_random_bytes([0x42; 16]).into_uuid();
        let request = sample_request(other_device_id);

        assert!(matches!(
            sign_request(&request, &identity),
            Err(SignatureError::SignerDeviceMismatch)
        ));
    }

    #[test]
    fn signed_request_debug_output_does_not_include_request_or_signature_bytes() {
        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let debug = format!("{signed:?}");

        assert!(!debug.contains("status.report"));
        assert!(!debug.contains("target"));
        assert_eq!(
            debug,
            format!(
                "SignedRequest {{ request_bytes_len: {}, signature_len: 64, .. }}",
                signed.request_bytes().len()
            )
        );
    }

    #[test]
    fn detached_signature_fields_are_kept_separate() {
        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let detached = SignedRequest {
            request_bytes: signed.request_bytes().to_vec(),
            signature: *signed.signature_bytes(),
        };

        assert_eq!(detached.request_bytes(), signed.request_bytes());
        assert_eq!(detached.signature_bytes(), signed.signature_bytes());
    }

    #[test]
    fn detached_parts_can_be_reconstructed_before_verification() {
        let (identity, request) = identity_and_request();
        let signed = sign_request(&request, &identity).expect("sign request");
        let reconstructed =
            SignedRequest::from_parts(signed.request_bytes().to_vec(), signed.signature_bytes())
                .expect("reconstruct detached request");
        let registered_key = VerifyingKey::from_bytes(&identity.public_key_bytes())
            .expect("registered public key is valid");

        assert_eq!(
            reconstructed.verify(identity.device_id(), &registered_key),
            Ok(request)
        );
    }
}
