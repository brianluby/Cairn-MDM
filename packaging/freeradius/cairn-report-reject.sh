#!/bin/sh
# Report an EAP-TLS Access-Reject to Cairn so a quarantined certificate can be
# proven rejected at this acceptance point. Called from FreeRADIUS post-auth on
# REJECT (see README.md beside this file). Exit 0 always: a reporting failure
# must never change the RADIUS decision.
#
# Environment (set by the exec module or the unit file):
#   CAIRN_URL          https://mdm.example.org
#   CAIRN_TOKEN_FILE   /etc/freeradius/cairn-ingest-token  (mode 0600)
#   CAIRN_POINT        this server's name as listed in radius.acceptance_points
# Argument 1: the client certificate serial (TLS-Client-Cert-Serial), hex.

serial=$(printf '%s' "${1:-}" | tr 'A-F' 'a-f' | tr -d ': ')
[ -n "$serial" ] || exit 0
[ -r "${CAIRN_TOKEN_FILE:-}" ] || exit 0
token=$(cat "$CAIRN_TOKEN_FILE")
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
body=$(printf '{"acceptance_point":"%s","serial":"%s","observed_at":"%s","source":"freeradius post-auth reject"}' "$CAIRN_POINT" "$serial" "$now")
curl -sS -m 5 -o /dev/null \
  -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  --data "$body" \
  "${CAIRN_URL%/}/api/v1/radius/rejections" >/dev/null 2>&1 || logger -t cairn-report-reject "report failed for serial $serial"
exit 0
