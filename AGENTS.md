# Shield Project Guidance

- Use **Shield** as the project name. DaemonONE is the target environment.
- Keep project descriptions factual and consistent with implemented features.
- Write documentation in clear, direct language suitable for a student
  engineering project.
- Use stable Rust and idiomatic, readable modules.
- Keep application logic in the library and `main.rs` small.
- Work only on the explicitly requested project phase.
- Use safe Rust; do not introduce `unsafe` without explicit approval.
- Validate security-sensitive inputs and fail closed as security features are
  introduced.
- Never hardcode or expose secrets, and never store private keys as plaintext.
- Do not execute arbitrary shell commands or expose an unrestricted shell.
- Use parameterized SQL for database work.
- Add tests for security behavior as each security module is implemented.
- Do not commit, push, merge, or reset without explicit approval.

Phase 3 adds fingerprint-checked manual enrollment, SQLite-backed trusted
device records, signature-based authentication, and revocation. Phase 4 adds
predefined task authorization with explicit per-device grants and parameter
allow-lists; authorization returns a decision and does not execute tasks.
Phase 5 adds timestamp validation and SQLite-backed replay prevention. Phase 6
adds versioned SQLite migrations and privacy-conscious security decision logs.
Networking is not implemented yet.
Never treat device discovery or request-supplied key material as proof of trust.
