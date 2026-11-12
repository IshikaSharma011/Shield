# Trusted Device Registry

## Three separate security steps

- **Enrollment** is an administrator's explicit decision to trust a device.
  Shield records its ID, public key, name, registration time, and trusted
  status after the public-key fingerprint matches a value checked out of band.
- **Authentication** checks that a signed request was made by the private-key
  holder for a known, non-revoked registry entry. Shield uses the key stored
  for that device ID; the request cannot supply its own trusted key.
- **Authorization** decides whether that authenticated device may perform a
  particular task. Task authorization is not implemented in this phase.

Finding or discovering a device is not enrollment and does not make it
trusted.

## Manual enrollment

On the device being enrolled, display its ID, public key, and fingerprint:

```sh
cargo run -- identity show
```

The operator should verify the SHA-256 fingerprint through a separate trusted
channel, such as an in-person comparison or a previously established secure
channel. Then enter the ID, public-key export, and verified fingerprint in
the enrollment command:

```sh
cargo run -- registry enroll \
  --database shield-registry.sqlite3 \
  --device-id <UUID> \
  --name <DEVICE_NAME> \
  --public-key <ED25519_PUBLIC_KEY> \
  --fingerprint <SHA256_FINGERPRINT>
```

The fingerprint format is `SHA256:` followed by the lowercase hexadecimal
SHA-256 digest of the 32 raw public-key bytes. Shield checks the entered value
against the supplied key. This check only confirms that the values match; the
operator must still verify the fingerprint independently. A mismatch fails
enrollment.

The registry rejects a device ID or public key that is already present. It
does not overwrite an existing record or silently restore a revoked device.
The SQLite database stores public keys and registration metadata only; private
keys remain in the OS credential store.

## Authentication and revocation

Library code authenticates a Phase 2 `SignedRequest` using:

```rust,ignore
let authenticated_request = registry.authenticate(&signed_request)?;
```

The registry reads the device ID from the request only to look up a record.
Unknown and revoked devices are rejected. For a trusted entry, Shield verifies
the detached signature with the key read from the registry. No network
transport is part of this phase.

List current records and revoke a device with:

```sh
cargo run -- registry list --database shield-registry.sqlite3
cargo run -- registry revoke --database shield-registry.sqlite3 --device-id <UUID>
```

Revocation preserves the record and changes its status. Repeating revocation
is safe. There is no un-revoke operation; an old registration cannot be
silently re-trusted.

## Storage and limitations

The registry uses SQLite and parameterized queries. The database contains
public data, but its integrity still matters: a user who can alter it could
change the trust decisions. Protect the database file with appropriate OS
account permissions and keep backups under the same access controls.

This phase does not authorize tasks, reject expired or replayed requests,
discover devices, or transmit registry changes to other devices. Operators
must distribute enrollment fingerprints and revocation decisions manually.
