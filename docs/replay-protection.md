# Replay Protection

Phase 5 prevents an authenticated request from being accepted more than once
by the same local registry while its timestamp remains valid.

## How request freshness works

`TaskRequest::new` uses the operating-system random source to create a request
ID and a 32-byte nonce, and records the current Unix time in milliseconds.
Phase 2 signs the canonical request bytes, which include the device ID, request
ID, timestamp, nonce, task ID, and parameters. Changing any of those fields
invalidates the signature.

After signature authentication, `ReplayProtection` checks that the timestamp
is no older than the configured maximum age and no farther in the future than
the configured clock-skew allowance. The default policy allows a request age
of five minutes and future clock skew of thirty seconds. Callers can construct
a different policy with `ReplayProtection::new`.

The nonce does not prove freshness by itself. The verifier also checks its
durable SQLite record, the request ID, and timestamp. A production network
protocol that needs protection against a client choosing its own predictable
nonce should add a verifier-issued challenge; this phase does not implement
networking or challenges.

## Atomic SQLite check

The replay table stores `(device_id, request_id)`, `(device_id, nonce)`, and
the time at which the request can no longer pass the age check. An immediate
SQLite transaction removes expired entries, checks for a previous ID or nonce,
and records the new values. The device ID comes from a registry-authenticated
request. SQLite serializes concurrent transactions, and unique constraints
provide a second guard against duplicate insertion. If storage is unavailable,
the request is rejected.

Request IDs and nonces are unique per device, not globally. Two devices may
use the same nonce without blocking one another.

## Retention and clock limits

Records remain until the request has passed its validity window. Expired
records are cleaned up during a later replay check, so an idle database may
retain old rows. Deleting the database or restoring an older backup removes
replay history; operators must preserve the registry database and its backups
to retain that protection.

Timestamp checks depend on the local system clock being reasonably accurate.
A bad clock can reject legitimate requests as expired or future-dated. This
does not provide trusted time, clock synchronization, or cross-machine replay
protection. There is no audit log in this phase.
