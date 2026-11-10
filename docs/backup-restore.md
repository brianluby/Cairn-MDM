# Backing up and restoring Cairn

Cairn's entire state is small and file-based. A correct backup is: the SQLite
database (captured consistently), the config, certificates, and the MFA encryption key. Losing
the database loses enrollments — treat it like the crown jewel it is.

## What to back up

| Item | Path (DZsec CT 226) | Why |
|---|---|---|
| Database | `/var/lib/cairn/cairn.db` (+ `-wal`, `-shm`) | Devices, enrollments, cert-auth associations, **APNs push cert/key**, embedded CA (generate/import mode), sessions, profiles, grants, audit |
| MFA key (candidate schema 027 onward) | `<storage.path>.mfa/key`, normally `/var/lib/cairn/cairn.db.mfa/key` | Decrypts confirmed and pending authenticator secrets; restore the matching key with the DB; directory 0700 and file 0600 |
| Config | `/etc/cairn/cairn.toml` | Wiring; references the cert/challenge files |
| Signing cert | `/etc/cairn/sign.crt` / `sign.key` | Profile-signing identity (re-issuable from LE, but back it up) |
| External SCEP chain / challenge | `/etc/cairn/dzsec-ca-chain.pem`, `/etc/cairn/scep-challenge` | External-mode enrollment trust + challenge |
| APNs push key (source) | `/var/lib/cairn/pushcert/push.key` | Only needed to re-import the APNs cert; the live cert is already in the DB |

The DB already contains the APNs cert+key and (in embedded modes) the CA key,
so the DB backup is confidential — store it encrypted, mode 0600.

## Backup bundle (recommended)

```
cairn backup -config /etc/cairn/cairn.toml -out /var/backups/cairn/cairn-$(date +%F-%H%M).tar.gz
```

One `tar.gz`, mode 0600, containing: `cairn.db` (an online `VACUUM INTO`
snapshot, integrity-checked), `mfa/key`, `config/cairn.toml` and every file the
configuration references (TLS and signing certificates and keys, CA import or
broker material, chain and secret files), plus `manifest.json` with the build,
schema versions, SHA-256 of every member, record counts (devices, pushable,
profiles, groups, grants, quarantined, MFA factors, local users) and the APNs
topics with expiry. The command then extracts the bundle into a scratch
directory and re-checks hashes, integrity and counts before reporting success.
A referenced file that is missing is recorded as a note, not an error; a
database with MFA factors but no key file is noted and fails verification. With
`alerts.webhook_url` set, success or failure is posted to the webhook, so a
timer that stops firing is caught by the stale-backup alert and a failing run
is announced immediately.

`packaging/systemd/cairn-backup.{service,timer}` run this nightly at 02:30 into
`/var/backups/cairn` and keep 14 bundles. Copy bundles off-host; they contain
private keys. `-db-only` keeps the older single-file snapshot behavior.

## Restore rehearsal

```
cairn restore -bundle /var/backups/cairn/cairn-2026-11-09-0230.tar.gz -rehearse
```

Extracts into a temporary directory, verifies every hash, runs
`PRAGMA integrity_check`, compares record counts and schema versions with the
manifest, checks that the MFA key is present when factors exist and that no
APNs certificate in the bundle has already expired, then deletes the scratch
directory (`-keep -workdir DIR` to inspect it). It never touches the live
database or starts a server. Rehearse monthly and after every upgrade.

To restore for real, `cairn restore -bundle FILE -into /path/to/empty/dir`
verifies first and refuses a bundle with problems or a non-empty target. It
writes `cairn.db`, `cairn.db.mfa/key` and `config/…` with 0600 permissions.
Point `storage.path` at the restored database, review the restored
`cairn.toml` and referenced files, run `cairn migrate`, then start. Never start
a restored copy where it can reach production devices unless it is the
production replacement.

## Consistent database backup (manual alternative)

SQLite in WAL mode must not be copied with a plain `cp` while Cairn is running —
you can capture a torn state. Use one of:

**A. `VACUUM INTO` (preferred, online, no lock contention):**
```
sqlite3 /var/lib/cairn/cairn.db "VACUUM INTO '/var/backups/cairn-$(date +%F).db'"
```
Produces a single consistent file with no WAL/SHM sidecars.

**B. Stop-copy (simplest, brief downtime):**
```
systemctl stop cairn
cp /var/lib/cairn/cairn.db /var/backups/cairn-$(date +%F).db
systemctl start cairn
```

Then bundle the rest:
```
tar czf /var/backups/cairn-config-$(date +%F).tgz \
  /etc/cairn/cairn.toml /etc/cairn/sign.crt /etc/cairn/sign.key \
  /etc/cairn/dzsec-ca-chain.pem /etc/cairn/scep-challenge
chmod 600 /var/backups/cairn-*.db /var/backups/cairn-config-*.tgz
```

Copy both off-host. `sqlite3` is a separate package on the CT
(`apt-get install -y sqlite3`); `VACUUM INTO` also works via a tiny Go/`cairn`
one-liner if you prefer not to install it.

## Integrity check

```
sqlite3 /var/backups/cairn-YYYY-MM-DD.db "PRAGMA integrity_check;"   # expect: ok
```

## Restore (into a disposable instance first — always test)

1. Provision a scratch CT/dir; install the same `cairn` binary version.
2. Restore files:
   ```
   install -o cairn -g cairn -m 0600 cairn-YYYY-MM-DD.db /var/lib/cairn/cairn.db
   rm -f /var/lib/cairn/cairn.db-wal /var/lib/cairn/cairn.db-shm   # stale sidecars
   tar xzf cairn-config-YYYY-MM-DD.tgz -C /
   ```
3. `cairn migrate -config /etc/cairn/cairn.toml` (applies any newer schema; a
   same-version restore is a no-op).
4. Start, then verify: `cairn version`, `cairn pushcert check` (topics + expiry
   present), the dashboard device count matches, and a device Refresh round-trips.

**Restore invariants** (same as migration): the restored instance must answer at
the same public URL and keep the same APNs topic and device-identity trust, or
enrolled devices won't recognize it. A restore onto the *same* hostname with the
*same* DB satisfies all of these automatically.

## Upgrades

Cairn auto-applies embedded schema migrations on start (append-only; each runs
once). The safe upgrade is: back up (above) → replace the binary → restart →
verify. Roll back by restoring the binary and, only if a migration ran that the
old binary can't read, the pre-upgrade DB. Schema migrations are additive
(`ADD COLUMN`, new tables), so an older binary generally still reads a
newer DB, but back up first regardless.

Rehearsed November 9, 2026, offline on a copy of the production database as it
stood under `c25eb67` (15 schema versions, 12 devices, 34 certificate
associations, 2 topics): the completion candidate's `migrate` took it to 32
versions with every count unchanged and integrity ok; `cairn backup` then
produced a bundle that `restore -rehearse` verified; the `c25eb67` binary run
against the upgraded database applied no migrations, read both APNs topics and
the local accounts, and left the schema at 32 with integrity ok. So a binary
rollback after this upgrade does not require a database rollback. The
rehearsal never started a server against the copied data.

## Schedule (recommendation)

Nightly `VACUUM INTO` + config tar to `/var/backups`, synced off-host (the
existing backup path / PBS). Keep ≥14 daily + ≥8 weekly. **Test a real restore
into a scratch instance quarterly** — an untested backup is a hope, not a backup.

## MFA key and recovery state

The completion candidate creates `<storage.path>.mfa/key` at server startup, or
when host bootstrap first runs. `cairn backup` includes it in the bundle and
verification fails when factors exist without it. The key is not
rotated during routine operation. A database backup alone cannot recover MFA.
Restore the matching directory/key before starting the restored service, owned
by the service user, directory mode 0700 and key mode 0600. Startup refuses to
create a replacement key when encrypted MFA state exists.

Restoring an old database also restores old MFA counters, sessions, approval
codes and recovery-code hashes. Before exposing a restored instance, invalidate
sessions and outstanding registrations and reset affected factors through a
reviewed recovery procedure. Do not assume a database restore preserves
single-use history from after the backup. End-to-end restore qualification is
still a release gate; never test a restored copy against production devices.
