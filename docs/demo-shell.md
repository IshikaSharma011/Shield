# Interactive Terminal Demonstration

Start the menu with:

```sh
cargo run -- demo
```

The session uses a new in-memory SQLite database. It cannot change an existing
registry database file, and registrations, permissions, replay records, and
audit events disappear when the demo exits.

To explicitly load a temporary sample device and its limited `status.report`
grant, run:

```sh
cargo run -- demo --setup-demo-data
```

Shield labels the sample as `[TEST DATA]`. The sample private key is generated
in memory and is never displayed or stored in SQLite. Without this option, the
menu starts with an empty registry.

## Professor walkthrough

1. Start with `cargo run -- demo --setup-demo-data` and point out that the
   console labels the sample device as test data and uses an isolated,
   in-memory registry.
2. Choose **2** to list the registered sample device and its fingerprint.
3. Choose **3**, select the sample device, enter `status.report`, then choose
   `summary` for its required `format` parameter.
4. Choose **4** and select request 1 to demonstrate signature authentication
   against the registered public key.
5. Choose **5** and select request 1 to show that the device's explicit grant
   and valid parameter schema allow authorization.
6. Choose **6** to submit a fresh request and then submit the same signed
   request again. The first passes and the replay is rejected by the SQLite
   replay check.
7. Choose **8** to run the full pipeline, demonstrate an ungranted task
   rejection, and replay a previously accepted request.
8. Choose **7** to view the stage decisions and final outcomes in the audit
   table, then choose **9** to exit.

To enroll a device yourself, use **1**. The shell creates an ephemeral identity
and displays its public key and fingerprint. Confirm the displayed fingerprint
at the prompt, then optionally grant one task explicitly. This local
demonstration simulates the operator's fingerprint comparison; production
manual enrollment still requires independent out-of-band verification.

Menu options **4** and **5** demonstrate the authentication and authorization
stages individually. Option **8** uses `SecurityEngine::process_request` for
the complete ordered pipeline. No option uses networking or executes a task
or operating-system command.
