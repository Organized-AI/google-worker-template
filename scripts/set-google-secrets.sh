#!/usr/bin/env bash
# Push the Google OAuth client credentials into the Worker as secrets.
#
# The OAuth *client* itself must be created in the Cloud Console — Google's
# OAuth client API produces IAP-locked clients tied to an internal brand and
# cannot create an external "Web application" client. Everything else
# (project, API enablement, secret upload) is automated.
#
# Usage:
#   ./scripts/set-google-secrets.sh                       # prompts for both
#   ./scripts/set-google-secrets.sh <CLIENT_ID> <SECRET>  # non-interactive
#
# Or point it at the JSON the Console gives you via "Download JSON":
#   ./scripts/set-google-secrets.sh ~/Downloads/client_secret_xxx.json

set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT="CHANGE-ME"
WORKER_URL="https://<worker>.<subdomain>.workers.dev"
REDIRECT_URI="${WORKER_URL}/oauth/callback"

CLIENT_ID="${1:-}"
CLIENT_SECRET="${2:-}"

# JSON download mode
if [[ -n "$CLIENT_ID" && "$CLIENT_ID" == *.json && -f "$CLIENT_ID" ]]; then
  echo "-> reading credentials from $CLIENT_ID"
  SRC="$CLIENT_ID"
  CLIENT_SECRET=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));w=d.get('web') or d.get('installed');print(w['client_secret'])" "$SRC")
  CLIENT_ID=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));w=d.get('web') or d.get('installed');print(w['client_id'])" "$SRC")
fi

if [[ -z "$CLIENT_ID" ]]; then
  echo "Create the client here, then paste the values below:"
  echo "  https://console.cloud.google.com/auth/clients?project=${PROJECT}"
  echo "  Type: Web application"
  echo "  Authorised redirect URI: ${REDIRECT_URI}"
  echo
  read -rp "GOOGLE_CLIENT_ID: " CLIENT_ID
fi
if [[ -z "$CLIENT_SECRET" ]]; then
  read -rsp "GOOGLE_CLIENT_SECRET: " CLIENT_SECRET
  echo
fi

if [[ "$CLIENT_ID" != *.apps.googleusercontent.com ]]; then
  echo "x that does not look like a Google client ID (expected *.apps.googleusercontent.com)" >&2
  exit 1
fi

printf '%s' "$CLIENT_ID"     | wrangler secret put GOOGLE_CLIENT_ID
printf '%s' "$CLIENT_SECRET" | wrangler secret put GOOGLE_CLIENT_SECRET

# Keep the local backup in sync with what the Worker holds.
BACKUP="$HOME/.google-orchestrator/secrets.env"
mkdir -p "$(dirname "$BACKUP")" && chmod 700 "$(dirname "$BACKUP")"
TMP=$(mktemp)
grep -v '^GOOGLE_CLIENT_' "$BACKUP" 2>/dev/null > "$TMP" || true
{ cat "$TMP"
  printf 'GOOGLE_CLIENT_ID=%s\nGOOGLE_CLIENT_SECRET=%s\n' "$CLIENT_ID" "$CLIENT_SECRET"; } > "$BACKUP"
rm -f "$TMP"
chmod 600 "$BACKUP"

echo
echo "-> verifying..."
sleep 4
curl -s "${WORKER_URL}/health" | python3 -c "
import json,sys
h=json.load(sys.stdin)
s=h['checks']['secrets']
print('  status  :', h['status'])
print('  secrets :', 'all configured' if s['configured'] else 'still missing '+', '.join(s['missing']))
"
echo
echo "Next: open ${WORKER_URL}/ and click 'connect account'."
