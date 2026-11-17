# Local account changes and session safety

Password resets, role changes and account deletion update the local account and
revoke its local sessions in one SQLite transaction. If session deletion fails,
the account change rolls back. The store refuses deletion or demotion of the
last local administrator inside that same transaction. The console now has a
working role-change backend.

These operations affect only sessions whose provider is `local`. A directory or
OIDC account with the same username is a separate identity. Local account changes
must not delete that identity's sessions.

A successful local password check carries an internal credential snapshot to
session creation. The session insert checks that the account still has that
password hash and role. A password reset, deletion or demotion between password
verification and session creation therefore rejects the stale login. The
snapshot stays in memory and is not serialized into a session or response.

Requests already authorized and executing when an account changes are not
retroactively interrupted. Directory session claims also remain snapshots;
authorization-bearing certificate issuance requires a fresh directory check,
MFA and its own reviewed authorization contract. These account changes do not
implement that contract.

Tests cover password and role revocation, stale login rejection, preservation
of a same-named LDAP session, rollback on session-delete failure and concurrent
attempts to remove the final two administrators.
