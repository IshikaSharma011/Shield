# Task Authorization

Phase 4 separates authentication from authorization. Authentication proves
that a request was signed by the key registered to a currently trusted
device. Authorization then checks whether that device has an explicit grant
for the requested task and whether the parameters match that task's schema.
A valid signature alone never grants access.

## Predefined task catalog

The catalog in `src/authorization.rs` is fixed in this phase:

| Task ID | Parameters |
| --- | --- |
| `status.report` | Required `format`: `summary` or `detailed` |
| `registry.list` | None |
| `device.info` | Required `section`: `identity` or `registry` |

Unknown task IDs, missing parameters, extra parameters, and values outside the
listed choices are rejected. Task requests cannot supply shell commands.
Authorization returns a structured decision and does not execute a task.

## Managing grants

Use the CLI to inspect the catalog and explicitly grant or remove a permission:

```text
shield authorization tasks
shield registry grant-task --database shield-registry.sqlite3 --device-id <UUID> --task-id status.report
shield registry revoke-task --database shield-registry.sqlite3 --device-id <UUID> --task-id status.report
```

Grants are stored in SQLite alongside device records. A grant can only be
created for a currently trusted device. Revoking a device prevents future
authorization even if it had a task grant. There are no default grants.

## Beginner example

Signing is like sealing a request so changes can be detected. Authentication
checks that the seal matches an enrolled device key. Authorization is a
separate permission check: for example, an authenticated device can request
`status.report` only after an operator grants that task, and it must choose
`format=summary` or `format=detailed`. These checks return a decision; there is
no task executor in this phase.

SQLite is local to one registry installation. Permission changes do not
synchronize to other machines, and replay prevention and audit logging are
not implemented yet.
