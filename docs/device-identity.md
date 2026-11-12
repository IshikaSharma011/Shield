# Device Identity

## What an identity contains

Each Shield identity has a random UUID and an Ed25519 signing key pair. The
UUID labels the device. The public key is safe to share for manual trusted-
device enrollment. The private signing key must remain secret.

## Creating and loading an identity

Create an identity once for the current OS account:

```sh
cargo run -- identity create
```

The generated UUID and private key are stored together as a versioned binary
credential in the operating system's credential store. The application does
not write a private-key file or use SQLite for key storage. If the OS store is
missing, locked, or inaccessible, creation fails without a plaintext fallback.

Load and display the saved identity with:

```sh
cargo run -- identity show
```

This prints the device ID and public key only. The private signing key is not
included in the identity's debug or display output.

## Exporting the public key

```sh
cargo run -- identity export-public-key
```

The command prints the algorithm label and public key in hexadecimal. Share
that value through a trusted channel when manually enrolling a device. No
network enrollment is implemented in this phase.

## Key storage and limitations

The selected credential store is platform-specific: Windows Credential
Manager, macOS Keychain, or a compatible Secret Service on Linux. A Linux
machine without an available Secret Service cannot create or load an identity
through Shield. Shield fails closed rather than storing the secret in a local
file.

The OS account and credential store must still be protected. A compromised
account or an unlocked store may expose the private key. The key is also in
process memory while loaded, so clearing temporary buffers does not guarantee
that every copy is erased by the runtime or OS.

There is no key rotation command. The Phase 3 registry can mark a local device
record revoked, but that status is not synchronized to other installations.
Replacing a key does not notify peers that already trusted the old public key;
operators must update those peers manually.
