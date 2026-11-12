# Signed Request Format

## The basic idea

A request is turned into one exact byte sequence before signing. The sender
signs every byte in that sequence with its Ed25519 private key. The signature
is stored separately from the request bytes.

For example, a request might describe task `status.report` with parameters
`mode=safe` and `target=node-7`. Shield serializes the protocol marker and
version, device ID, request ID, timestamp, nonce, task ID, and parameters.
Signing that sequence produces a separate 64-byte signature. A verifier checks
those original bytes with the public key registered for the request's device
ID.

## Version 1 binary layout

All integer lengths and timestamps use unsigned big-endian byte order. UUIDs
are their 16 raw bytes. Text is UTF-8. Parameter keys are serialized in sorted
order; this means the same request data always produces the same bytes.

| Field | Encoding |
| --- | --- |
| Format marker | 4 bytes: ASCII `SHLD` |
| Protocol version | 1 byte: `0x01` |
| Device ID | 16 UUID bytes |
| Request ID | 16 UUID bytes |
| Timestamp | 8-byte Unix time in milliseconds |
| Nonce | 32 random bytes |
| Task ID | 2-byte length, then UTF-8 bytes |
| Parameter count | 2-byte unsigned count |
| Each parameter | 2-byte key length + key bytes, then 2-byte value length + value bytes |

The serializer limits a request to 1 MiB, 128 parameters, and 4096 UTF-8
bytes per task ID, parameter key, or value. The parser rejects unsupported
versions, truncated fields, invalid UTF-8, duplicate or out-of-order
parameters, and trailing bytes.

## Signing and verification

`TaskRequest::serialize` creates the versioned request bytes. `sign_request`
signs that exact byte vector and returns a `SignedRequest` containing separate
request and signature fields. Verification parses the request strictly, checks
that its device ID matches the registered ID supplied by the caller, then
verifies the signature over the original bytes. The public key is an explicit
verification argument; it is never taken from the request.

Example call flow:

```rust,ignore
let request = TaskRequest::new(device_id, "status.report", parameters)?;
let signed = sign_request(&request, &sender_identity)?;

// The caller gets this key from its trusted-device registry using device_id.
let verified = signed.verify(device_id, &registered_public_key)?;
```

The example shows the API flow only. Shield does not yet implement a trusted-
device registry or network transport.

## What verification proves

Successful verification means the exact bytes were signed by the private key
that matches the supplied public key, and the request's device ID matches the
registered ID passed to the verifier. It does not determine whether the
device is trusted, whether the task is authorized, whether the timestamp is
fresh, or whether the nonce has been used before. Those checks belong to later
phases.
