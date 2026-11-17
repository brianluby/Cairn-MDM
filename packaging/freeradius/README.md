# Reporting EAP-TLS rejections to Cairn

Cairn releases a quarantined certificate issuance only after every RADIUS
acceptance point has reported an observed Access-Reject for each enumerated
serial (see `docs/quarantine-resolution.md`). This directory holds the
FreeRADIUS side of that report.

1. Install `cairn-report-reject.sh` to `/usr/local/sbin/`, and the ingest token
   (from `radius.ingest_token_file` on the Cairn host) to
   `/etc/freeradius/cairn-ingest-token`, mode 0600, owned by the FreeRADIUS user.
2. Define an `exec` module instance, for example in `mods-available/cairn_report`:

   ```
   exec cairn_report {
       wait = no
       program = "/usr/local/sbin/cairn-report-reject.sh %{TLS-Client-Cert-Serial}"
       input_pairs = request
       shell_escape = yes
       env_inherit = no
   }
   ```

   and export the environment in the unit file or `radiusd.conf`:
   `CAIRN_URL`, `CAIRN_TOKEN_FILE`, `CAIRN_POINT` (this server's name exactly as
   it appears in Cairn's `radius.acceptance_points`).
3. Call it from the EAP-TLS virtual server's post-auth reject section:

   ```
   post-auth {
       Post-Auth-Type REJECT {
           cairn_report
       }
   }
   ```

`TLS-Client-Cert-Serial` is set by the EAP-TLS module when the client presented a
certificate; the script does nothing when it is empty. `wait = no` keeps the
report off the authentication path, and the script always exits 0, so a failed
report never changes the RADIUS decision. Cairn records the serial, acceptance
point and time; it accepts only the acceptance points it is configured with.

Test after installing: present a revoked certificate from a client, confirm the
reject in the FreeRADIUS log, then confirm the row on Cairn's quarantine detail
page or with `sqlite3 cairn.db 'select * from radius_rejections'`.
