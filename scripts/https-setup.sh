#!/usr/bin/env bash
# Advisory Hub — HTTPS setup for a deployment.
#
# Installs a TLS certificate for the nginx proxy in docker-compose.https.yml,
# validates it, and points .env at the HTTPS compose overlay. Nothing here
# runs automatically; it is meant to be run by whoever deploys, on the
# deployment host, from the repository root.
#
# Does not apply to docker-compose.prod.no-proxy.yml — that file has no TLS
# listener at all; it expects an enterprise WAF/reverse proxy outside Docker
# to terminate TLS. See docs/deployment.md §1b.
#
# Full walkthrough: docs/operations.md §7.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
COMPOSE_FILES="docker-compose.yml:docker-compose.https.yml"
PROD_COMPOSE_FILE="docker-compose.prod.yml"   # TLS built in; left as-is
NO_PROXY_COMPOSE_FILE="docker-compose.prod.no-proxy.yml"   # no TLS listener in this file at all; this script does not apply (docs/deployment.md §1b)
EXPIRY_WARN_DAYS=30
CLEANUP=()
trap 'rm -f ${CLEANUP[@]+"${CLEANUP[@]}"}' EXIT

# ─── output helpers ──────────────────────────────────────────────────────────
info() { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: scripts/https-setup.sh <command> [options]

Commands
  install     Install an existing certificate + key (from your CA) and enable HTTPS
  csr         Generate a private key + certificate signing request for your CA
  self-signed Generate a self-signed certificate (testing / pre-CA only)
  check       Validate the installed certificate (expiry, key match, hostname)
  enable      Point .env at the HTTPS overlay (certificate must already be installed).
              If .env already uses docker-compose.prod.yml, only SERVER_NAME is set.
  disable     Remove the HTTPS overlay from .env (back to plain HTTP on APP_PORT).
              Refused for docker-compose.prod.yml, which is HTTPS-only.

Options
  --server-name NAME   Hostname users browse to, e.g. advisoryhub.corp.example
                       (install/csr/self-signed/enable; default: SERVER_NAME from .env)
  --san LIST           Extra subjectAltNames, comma-separated,
                       e.g. "DNS:advisoryhub,IP:10.0.4.20"   (csr/self-signed)
  --cert FILE          Certificate in PEM (install). May already include the chain.
  --key FILE           Unencrypted private key in PEM (install)
  --chain FILE         Intermediate CA certificate(s) in PEM, appended to --cert (install)
  --ca FILE            Root CA in PEM; if given, the chain is verified against it (install)
  --days N             Validity for self-signed (default 397)
  --cert-dir DIR       Where certs live on the host (default: TLS_CERT_DIR from .env, else ./certs)
  --reload             After install, reload nginx if the proxy is already running
  -h, --help           Show this help

Examples
  # 1. Internal CA: create a CSR, send certs/server.csr to the CA, then install the result
  scripts/https-setup.sh csr --server-name advisoryhub.corp.example --san "DNS:advisoryhub"
  scripts/https-setup.sh install --cert signed.crt --chain intermediate.crt \
      --key certs/server.key --server-name advisoryhub.corp.example

  # 2. Certificate + key already issued elsewhere
  scripts/https-setup.sh install --cert fullchain.pem --key privkey.pem \
      --server-name advisoryhub.corp.example --reload
EOF
}

# ─── .env helpers ────────────────────────────────────────────────────────────
env_get() {  # env_get KEY → value from .env, or empty
  [[ -f "$ENV_FILE" ]] || return 0
  awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); v = $0 } END { print v }' "$ENV_FILE"
}

env_set() {  # env_set KEY VALUE — replace in place, or append
  local key="$1" val="$2" tmp
  [[ -f "$ENV_FILE" ]] || die "$ENV_FILE not found — copy .env.example to .env first (docs/operations.md §0)"
  tmp="$(mktemp)"
  awk -F= -v k="$key" -v v="$val" '
    $1 == k { if (!done) print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$ENV_FILE" >"$tmp"
  cat "$tmp" >"$ENV_FILE"   # keep the original file's permissions/ownership
  rm -f "$tmp"
  ok ".env: $key=$val"
}

env_unset() {
  local key="$1" tmp
  [[ -f "$ENV_FILE" ]] || return 0
  tmp="$(mktemp)"
  awk -F= -v k="$key" '$1 != k' "$ENV_FILE" >"$tmp"
  cat "$tmp" >"$ENV_FILE"
  rm -f "$tmp"
  ok ".env: removed $key"
}

# ─── certificate helpers ─────────────────────────────────────────────────────
require_openssl() {
  command -v openssl >/dev/null || die "openssl is required"
}

pubkey_hash_cert() { openssl x509 -in "$1" -noout -pubkey | openssl sha256 | awk '{print $NF}'; }
pubkey_hash_key()  { openssl pkey -in "$1" -pubout 2>/dev/null | openssl sha256 | awk '{print $NF}'; }

san_ext() {  # san_ext NAME EXTRA → "subjectAltName=DNS:NAME,EXTRA"
  local name="$1" extra="$2" first
  if [[ "$name" =~ ^[0-9.]+$ || "$name" == *:* ]]; then first="IP:$name"; else first="DNS:$name"; fi
  if [[ -n "$extra" ]]; then printf 'subjectAltName=%s,%s' "$first" "$extra"; else printf 'subjectAltName=%s' "$first"; fi
}

validate() {  # validate CERT KEY NAME [LABEL] — exits non-zero on any hard failure
  local cert="$1" key="$2" name="$3" label="${4:-$1}" end_date
  openssl x509 -in "$cert" -noout 2>/dev/null || die "$label is not a PEM certificate"
  openssl pkey -in "$key" -passin pass: -noout 2>/dev/null \
    || die "$key is not a readable, unencrypted PEM private key (nginx cannot prompt for a passphrase — decrypt it with: openssl pkey -in $key -out server.key)"
  ok "certificate and key parse"

  [[ "$(pubkey_hash_cert "$cert")" == "$(pubkey_hash_key "$key")" ]] \
    || die "private key does not match the certificate"
  ok "private key matches certificate"

  end_date="$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
  openssl x509 -in "$cert" -noout -checkend 0 >/dev/null || die "certificate expired on $end_date"
  if ! openssl x509 -in "$cert" -noout -checkend $((EXPIRY_WARN_DAYS * 86400)) >/dev/null; then
    warn "certificate expires within $EXPIRY_WARN_DAYS days ($end_date)"
  else
    ok "valid until $end_date"
  fi

  if [[ -n "$name" ]]; then
    local flag="-checkhost"
    [[ "$name" =~ ^[0-9.]+$ || "$name" == *:* ]] && flag="-checkip"
    if openssl x509 -in "$cert" -noout "$flag" "$name" | grep -q "does match"; then
      ok "certificate covers $name"
    else
      die "certificate does not cover $name (check its subjectAltName)"
    fi
  fi

  if [[ "$(openssl x509 -in "$cert" -noout -subject | sed 's/^subject=//')" \
     == "$(openssl x509 -in "$cert" -noout -issuer | sed 's/^issuer=//')" ]]; then
    warn "certificate is self-signed — browsers will warn until it is trusted on each client"
  fi
}

backup_existing() {
  local f ts
  ts="$(date +%Y%m%d-%H%M%S)"
  for f in "$CERT_DIR/server.crt" "$CERT_DIR/server.key"; do
    [[ -f "$f" ]] && cp -p "$f" "$f.bak-$ts" && info "backed up $(basename "$f") → $(basename "$f").bak-$ts"
  done
  return 0
}

same_file() { [[ "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" == "$(cd "$(dirname "$2")" && pwd)/$(basename "$2")" ]]; }

# ─── commands ────────────────────────────────────────────────────────────────
cmd_enable() {
  [[ -n "$SERVER_NAME" ]] || die "--server-name is required (or set SERVER_NAME in .env)"
  [[ -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]] \
    || die "no certificate in $CERT_DIR — run 'install', 'csr' then 'install', or 'self-signed' first"
  env_set SERVER_NAME "$SERVER_NAME"
  if [[ "$(env_get COMPOSE_FILE)" == "$PROD_COMPOSE_FILE" ]]; then
    ok "using $PROD_COMPOSE_FILE (HTTPS built in)"
  else
    env_set SESSION_COOKIE_SECURE true
    env_set COMPOSE_FILE "$COMPOSE_FILES"
  fi
  [[ "$CERT_DIR" != "$ROOT/certs" ]] && env_set TLS_CERT_DIR "$CERT_DIR"
  echo
  info "HTTPS is configured. Start or restart the stack:"
  info "  docker compose up -d --remove-orphans"
  info "then browse to https://$SERVER_NAME$( [[ "$(env_get HTTPS_PORT)" =~ ^(|443)$ ]] || printf ':%s' "$(env_get HTTPS_PORT)")/"
}

cmd_install() {
  require_openssl
  [[ -n "$CERT" && -n "$KEY" ]] || die "install needs --cert and --key"
  [[ -f "$CERT" ]] || die "$CERT not found"
  [[ -f "$KEY" ]] || die "$KEY not found"
  [[ -z "$CHAIN" || -f "$CHAIN" ]] || die "$CHAIN not found"
  [[ -n "$SERVER_NAME" ]] || die "--server-name is required (or set SERVER_NAME in .env)"

  local bundle
  bundle="$(mktemp)"
  CLEANUP+=("$bundle")
  cat "$CERT" >"$bundle"
  [[ -n "$CHAIN" ]] && { echo >>"$bundle"; cat "$CHAIN" >>"$bundle"; }

  echo "Validating"
  validate "$bundle" "$KEY" "$SERVER_NAME" "$CERT"
  if [[ -n "$CA" ]]; then
    [[ -f "$CA" ]] || die "$CA not found"
    if openssl verify -CAfile "$CA" -untrusted "$bundle" "$bundle" >/dev/null 2>&1; then
      ok "chain verifies against $(basename "$CA")"
    else
      die "chain does not verify against $CA — is an intermediate missing? (use --chain)"
    fi
  fi

  echo "Installing into $CERT_DIR"
  mkdir -p "$CERT_DIR"
  backup_existing
  cp "$bundle" "$CERT_DIR/server.crt"
  chmod 644 "$CERT_DIR/server.crt"
  if ! same_file "$KEY" "$CERT_DIR/server.key"; then
    (umask 077; cp "$KEY" "$CERT_DIR/server.key")
  fi
  chmod 600 "$CERT_DIR/server.key"
  ok "server.crt (644), server.key (600)"
  rm -f "$CERT_DIR/server.csr"

  echo "Configuring"
  cmd_enable

  if [[ "$RELOAD" == 1 ]]; then
    echo
    if (cd "$ROOT" && docker compose ps --status running --services 2>/dev/null | grep -qx proxy); then
      (cd "$ROOT" && docker compose exec proxy nginx -t && docker compose exec proxy nginx -s reload)
      ok "nginx reloaded with the new certificate"
    else
      info "proxy is not running yet — 'docker compose up -d --remove-orphans' will pick the certificate up"
    fi
  fi
}

cmd_csr() {
  require_openssl
  [[ -n "$SERVER_NAME" ]] || die "--server-name is required"
  mkdir -p "$CERT_DIR"
  [[ -f "$CERT_DIR/server.key" ]] && die "$CERT_DIR/server.key already exists — move it aside first so a live key is never overwritten"
  (umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$CERT_DIR/server.key" 2>/dev/null)
  openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -subj "/CN=$SERVER_NAME" -addext "$(san_ext "$SERVER_NAME" "$SAN")"
  ok "private key: $CERT_DIR/server.key (600 — never send this anywhere)"
  ok "CSR:         $CERT_DIR/server.csr"
  echo
  info "Send server.csr to your certificate authority. When the signed certificate comes back:"
  info "  scripts/https-setup.sh install --cert <signed.crt> [--chain <intermediate.crt>] \\"
  info "      --key $CERT_DIR/server.key --server-name $SERVER_NAME"
}

cmd_self_signed() {
  require_openssl
  [[ -n "$SERVER_NAME" ]] || die "--server-name is required"
  warn "self-signed certificates are for testing or bridging until a CA-issued one arrives"
  mkdir -p "$CERT_DIR"
  backup_existing
  (umask 077; openssl req -x509 -newkey rsa:3072 -nodes -days "$DAYS" \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/CN=$SERVER_NAME" -addext "$(san_ext "$SERVER_NAME" "$SAN")" 2>/dev/null)
  chmod 644 "$CERT_DIR/server.crt"
  chmod 600 "$CERT_DIR/server.key"
  ok "generated $CERT_DIR/server.crt (valid $DAYS days)"
  validate "$CERT_DIR/server.crt" "$CERT_DIR/server.key" "$SERVER_NAME"
  echo "Configuring"
  # A browser that has seen HSTS for this host will refuse to let a user
  # click through a certificate warning, so keep it off until a real cert.
  env_set HSTS_MAX_AGE 0
  cmd_enable
  info "HSTS was set to 0 for the self-signed period — remove HSTS_MAX_AGE from .env once a CA-issued certificate is installed"
}

cmd_check() {
  require_openssl
  [[ -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]] || die "no certificate installed in $CERT_DIR"
  echo "Checking $CERT_DIR"
  validate "$CERT_DIR/server.crt" "$CERT_DIR/server.key" "$SERVER_NAME"
  info "subject: $(openssl x509 -in "$CERT_DIR/server.crt" -noout -subject | sed 's/^subject=//')"
  info "issuer:  $(openssl x509 -in "$CERT_DIR/server.crt" -noout -issuer | sed 's/^issuer=//')"
  case "$(env_get COMPOSE_FILE)" in
    "$PROD_COMPOSE_FILE") ok ".env uses $PROD_COMPOSE_FILE (HTTPS built in)" ;;
    "$COMPOSE_FILES")     ok ".env uses the HTTPS overlay" ;;
    *)                    warn ".env uses neither the production file nor the HTTPS overlay — run 'enable'" ;;
  esac
}

cmd_disable() {
  [[ "$(env_get COMPOSE_FILE)" == "$PROD_COMPOSE_FILE" ]] \
    && die "$PROD_COMPOSE_FILE always serves HTTPS — there is nothing to disable"
  env_unset COMPOSE_FILE
  echo
  info "HTTPS overlay removed. Apply with: docker compose up -d --remove-orphans"
  info "SESSION_COOKIE_SECURE is still true — log-in over plain HTTP will not work"
  info "unless something else in front of the app terminates TLS."
}

# ─── argument parsing ────────────────────────────────────────────────────────
[[ $# -gt 0 ]] || { usage; exit 1; }
COMMAND="$1"; shift
SERVER_NAME="" SAN="" CERT="" KEY="" CHAIN="" CA="" DAYS=397 CERT_DIR="" RELOAD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-name) SERVER_NAME="${2:?}"; shift 2 ;;
    --san)         SAN="${2:?}"; shift 2 ;;
    --cert)        CERT="${2:?}"; shift 2 ;;
    --key)         KEY="${2:?}"; shift 2 ;;
    --chain)       CHAIN="${2:?}"; shift 2 ;;
    --ca)          CA="${2:?}"; shift 2 ;;
    --days)        DAYS="${2:?}"; shift 2 ;;
    --cert-dir)    CERT_DIR="${2:?}"; shift 2 ;;
    --reload)      RELOAD=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "unknown option: $1 (see --help)" ;;
  esac
done

SERVER_NAME="${SERVER_NAME:-$(env_get SERVER_NAME)}"
CERT_DIR="${CERT_DIR:-$(env_get TLS_CERT_DIR)}"
CERT_DIR="${CERT_DIR:-$ROOT/certs}"
[[ "$CERT_DIR" = /* ]] || CERT_DIR="$ROOT/${CERT_DIR#./}"

if [[ "$COMMAND" != "-h" && "$COMMAND" != "--help" && "$COMMAND" != "help" ]] \
   && [[ "$(env_get COMPOSE_FILE)" == "$NO_PROXY_COMPOSE_FILE" ]]; then
  die "$NO_PROXY_COMPOSE_FILE has no TLS listener to configure — it expects TLS to be terminated by an enterprise WAF/reverse proxy outside Docker (docs/deployment.md §1b, D-040)"
fi

case "$COMMAND" in
  install)     cmd_install ;;
  csr)         cmd_csr ;;
  self-signed) cmd_self_signed ;;
  check)       cmd_check ;;
  enable)      cmd_enable ;;
  disable)     cmd_disable ;;
  -h|--help|help) usage ;;
  *)           usage; exit 1 ;;
esac
