#!/usr/bin/env bash
# Prepare a legacy Community installation for an HTTPS-only introspection
# release. This script never restarts services or changes Git/Docker state.
# Default mode is dry-run; --apply changes ONLY .env after a successful probe.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

case "${1:-}" in
  ""|--check) apply=0 ;;
  --apply) apply=1 ;;
  *) echo "Usage: bash scripts/prepare-https-introspection.sh [--check|--apply]" >&2; exit 2 ;;
esac

if [ -L .env ] || [ ! -f .env ] || [ -L backups ] || { [ -e backups ] && [ ! -d backups ]; }; then
  echo "BLOCKED: .env or backups path is missing or unsafe." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "BLOCKED: Docker is required to verify HTTPS from Gateway's actual network." >&2
  exit 1
fi

set -a
# Same operator-owned .env contract as scripts/update.sh.
. ./.env
set +a

if [ "${VPS_AGENT_AUTH_MODE:-}" != integrated ]; then
  echo "BLOCKED: this migration is valid only for integrated OAuth installations." >&2
  exit 1
fi
domain="${VPS_AGENT_DOMAIN:-}"
if ! [[ "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] || [[ "$domain" == *..* ]]; then
  echo "BLOCKED: an unambiguous registered HTTPS domain is required." >&2
  exit 1
fi
target="https://$domain/oauth/v2/introspect"
legacy="http://zitadel-auth-internal:8080/oauth/v2/introspect"
current="${VPS_AGENT_INTEGRATED_INTROSPECTION_URL:-}"
if [ "$current" != "$legacy" ] && [ "$current" != "$target" ]; then
  echo "BLOCKED: unknown introspection endpoint; do not overwrite custom operator settings." >&2
  exit 1
fi
if [ -z "${VPS_AGENT_INTEGRATED_INTROSPECTION_CLIENT_ID:-}" ] ||
   [ -z "${VPS_AGENT_INTEGRATED_INTROSPECTION_CLIENT_SECRET:-}" ]; then
  echo "BLOCKED: dedicated introspection credentials are missing." >&2
  exit 1
fi

compose=(docker compose -f compose.yaml -f compose.integrated-auth.yaml)
if [ "${VPS_AGENT_WHOLE_HOST:-0}" = 1 ]; then
  compose+=(-f compose.host.yaml)
fi
if [ "${VPS_AGENT_BUNDLED_PROXY:-0}" = 1 ]; then
  compose+=(-f compose.integrated-auth.proxy.yaml)
fi

tmp="$(mktemp -d)"
chmod 700 "$tmp"
trap 'rm -rf -- "$tmp"' EXIT

echo "Checking trusted HTTPS introspection from a disposable Gateway container..."
# -e supplies the target only to a disposable container, not the live one.
# Curl does not follow redirects, does not inherit a proxy, and validates TLS.
if ! "${compose[@]}" run --rm -T --no-deps \
  -e "VPS_AGENT_INTEGRATED_INTROSPECTION_URL=$target" \
  --entrypoint /bin/sh gateway -ceu '
    exec curl --noproxy "*" --proto "=https" --max-redirs 0 \
      --fail --silent --show-error --connect-timeout 5 --max-time 12 \
      --request POST --url "$VPS_AGENT_INTEGRATED_INTROSPECTION_URL" \
      --user "$VPS_AGENT_INTEGRATED_INTROSPECTION_CLIENT_ID:$VPS_AGENT_INTEGRATED_INTROSPECTION_CLIENT_SECRET" \
      --header "Content-Type: application/x-www-form-urlencoded" \
      --data "token=deliberately-invalid-migration-preflight"
  ' >"$tmp/response.json"; then
  echo "BLOCKED: trusted HTTPS introspection was not reachable from Gateway's network." >&2
  exit 1
fi
python3 - "$tmp/response.json" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as fp:
    result=json.load(fp)
if result.get("active") is not False:
    raise SystemExit("BLOCKED: unexpected HTTPS introspection response")
PY

if [ "$current" = "$target" ]; then
  echo "PASS: HTTPS endpoint already configured and checked. No files changed."
  exit 0
fi
if [ "$apply" != 1 ]; then
  echo "PASS: HTTPS preflight succeeded. Dry run only; no files changed."
  exit 0
fi

# No running container is restarted. Existing old Gateway process keeps its
# previous configuration until the operator authorizes a reviewed updater.
mkdir -p backups
chmod 700 backups
backup="$(mktemp -d backups/https-introspection.XXXXXXXX)"
chmod 700 "$backup"
cp -- .env "$backup/previous.env"
chmod 600 "$backup/previous.env"

python3 - "$target" <<'PY'
import os,pathlib,sys,tempfile
path=pathlib.Path(".env")
if path.is_symlink() or not path.is_file():
    raise SystemExit("BLOCKED: unsafe .env path")
content=path.read_text(encoding="utf-8")
prefix="VPS_AGENT_INTEGRATED_INTROSPECTION_URL="
lines=content.splitlines(keepends=True)
matches=[i for i,line in enumerate(lines) if line.startswith(prefix)]
if len(matches)!=1:
    raise SystemExit("BLOCKED: expected one introspection endpoint assignment")
new=prefix+sys.argv[1]+("\n" if lines[matches[0]].endswith("\n") else "")
lines[matches[0]]=new
fd,temporary=tempfile.mkstemp(prefix=".introspection-migrate-",dir=".")
try:
    with os.fdopen(fd,"w",encoding="utf-8") as out:
        out.write("".join(lines))
        out.flush()
        os.fsync(out.fileno())
    os.chmod(temporary,0o600)
    os.replace(temporary,path)
except BaseException:
    try: os.unlink(temporary)
    except OSError: pass
    raise
PY
echo "PASS: HTTPS config prepared with a private backup. No services restarted."
echo "Next step: independently validate a signed update candidate and its rollback."
