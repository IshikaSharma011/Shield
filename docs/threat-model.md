# Initial Threat Model

## System in scope

Phase 0 consists of a local Rust command-line application that prints a
welcome message. Clap parses its arguments and provides help and version
output.

## Security objectives

This phase has no authentication or authorization objective. It introduces no
network listener, key material, database, or privileged operation.

## Out of scope

Device impersonation, forged signatures, replayed requests, unauthorized task
execution, key theft, malicious network traffic, and audit-log tampering are
not mitigated because the corresponding security features do not yet exist.

## Assumptions and limitations

The CLI runs as the invoking user and only displays static application text.
Successful compilation and a smoke test establish basic behavior; they do not
demonstrate that future security controls are effective. Each later phase
must update this model to cover its new assets, trust boundaries, threats,
and mitigations.
