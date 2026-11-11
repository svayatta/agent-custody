#!/bin/sh
# Starts the log server. Generates the signing key on first run and prints the public key, which is what you hand
# to anyone who verifies receipts logged here. The token comes from AGENT_CUSTODY_LOG_TOKEN; without one the log
# accepts appends from anyone who can reach the port, which is only acceptable behind a private network.
set -eu

: "${AGENT_CUSTODY_LOG_FILE:=/data/log.jsonl}"
: "${AGENT_CUSTODY_LOG_KEY:=/data/keys/log.key}"
: "${AGENT_CUSTODY_LOG_PORT:=8787}"
# Optional: the id written into every tree head, and a tenants file for several logs behind one server.
log_id_args=""
[ -n "${AGENT_CUSTODY_LOG_ID:-}" ] && log_id_args="--log-id $AGENT_CUSTODY_LOG_ID"
[ -n "${AGENT_CUSTODY_LOG_TENANTS:-}" ] && log_id_args="$log_id_args --tenants $AGENT_CUSTODY_LOG_TENANTS"
# With DATABASE_URL the logs, tenants, and tokens live in Postgres; the file is not used.
[ -n "${DATABASE_URL:-}" ] && log_id_args="$log_id_args --db-env DATABASE_URL"
# TRUST_PROXY=1 when a reverse proxy you run (the compose Caddy) is the only way in: limits are then per real client.
[ "${TRUST_PROXY:-0}" = "1" ] && log_id_args="$log_id_args --trust-proxy"
# AGENT_CUSTODY_HASH_ONLY=1 refuses full leaves at append: a log run for other people never receives a receipt.
[ "${AGENT_CUSTODY_HASH_ONLY:-0}" = "1" ] && log_id_args="$log_id_args --hash-only"
# ADMIN_TOKEN turns on the operator's page at /admin; the public URLs fill the welcome sheet in.
if [ -n "${ADMIN_TOKEN:-}" ]; then
  log_id_args="$log_id_args --admin-token-env ADMIN_TOKEN"
  [ -n "${LOG_HOST:-}" ] && log_id_args="$log_id_args --public-url https://$LOG_HOST/"
  [ -n "${CHECKPOINTS_HOST:-}" ] && log_id_args="$log_id_args --checkpoints-url https://$CHECKPOINTS_HOST/"
fi
# Checkpoints go to this directory (served by the checkpoints host) every AGENT_CUSTODY_CHECKPOINT_EVERY seconds.
[ -n "${AGENT_CUSTODY_CHECKPOINT_DIR:-}" ] && log_id_args="$log_id_args --checkpoint-dir $AGENT_CUSTODY_CHECKPOINT_DIR --checkpoint-every ${AGENT_CUSTODY_CHECKPOINT_EVERY:-300} --checkpoint-heartbeat ${AGENT_CUSTODY_CHECKPOINT_HEARTBEAT:-21600}"
# ROLE=witness runs the witness: countersigns the log's checkpoints into /witnessed, served by the witness host.
if [ "${ROLE:-log}" = "witness" ]; then
  key_dir=$(dirname "$AGENT_CUSTODY_LOG_KEY"); key_name=$(basename "$AGENT_CUSTODY_LOG_KEY" .key)
  mkdir -p "$key_dir" /witnessed
  [ -f "$AGENT_CUSTODY_LOG_KEY" ] || agent-custody keygen --dir "$key_dir" --name "$key_name" >&2
  echo "agent-custody witness: public key (verifiers fetch it from the witness host's /.well-known/agent-custody-witness.json):" >&2
  cat "$key_dir/$key_name.pub" >&2
  tenant_args=""
  for t in $(printf '%s' "${WITNESS_TENANTS:-default}" | tr ',' ' '); do tenant_args="$tenant_args --tenant $t"; done
  exec agent-custody witness --key "$AGENT_CUSTODY_LOG_KEY" --log-url "$WITNESS_LOG_URL" --checkpoints-url "$WITNESS_CHECKPOINTS_URL" --out /witnessed --every "${WITNESS_EVERY:-300}" $tenant_args
fi
# ROLE=portal runs the tenant portal: registration, keys, usage, billing, on the same Postgres as the log.
if [ "${ROLE:-log}" = "portal" ]; then
  portal_args="--db-env DATABASE_URL --secret-env PORTAL_SECRET --public-url https://${LOG_HOST:?LOG_HOST is required for the portal}/ --host 0.0.0.0 --port ${AGENT_CUSTODY_PORTAL_PORT:-8792}"
  [ -n "${CHECKPOINTS_HOST:-}" ] && portal_args="$portal_args --checkpoints-url https://$CHECKPOINTS_HOST/"
  [ -n "${PORTAL_HOST:-}" ] && portal_args="$portal_args --portal-url https://$PORTAL_HOST/"
  [ -n "${STRIPE_SECRET_KEY:-}" ] && portal_args="$portal_args --stripe-key-env STRIPE_SECRET_KEY --stripe-webhook-env STRIPE_WEBHOOK_SECRET --stripe-price-team ${STRIPE_PRICE_TEAM:?STRIPE_PRICE_TEAM is required with STRIPE_SECRET_KEY}"
  # MAIL_FROM is an address only (no display name): the arguments are word-split below
  [ -n "${MAIL_API_KEY:-}" ] && portal_args="$portal_args --mail-key-env MAIL_API_KEY --mail-from ${MAIL_FROM:?MAIL_FROM is required with MAIL_API_KEY}"
  [ -n "${MAIL_NOTIFY:-}" ] && portal_args="$portal_args --mail-notify $MAIL_NOTIFY"
  [ -n "${MAIL_REPLY_TO:-}" ] && portal_args="$portal_args --mail-reply-to $MAIL_REPLY_TO"
  [ -n "${GITHUB_CLIENT_ID:-}" ] && portal_args="$portal_args --github-client-id $GITHUB_CLIENT_ID --github-secret-env GITHUB_CLIENT_SECRET"
  [ -n "${GOOGLE_CLIENT_ID:-}" ] && portal_args="$portal_args --google-client-id $GOOGLE_CLIENT_ID --google-secret-env GOOGLE_CLIENT_SECRET"
  [ "${TRUST_PROXY:-}" = "1" ] && portal_args="$portal_args --trust-proxy"
  # shellcheck disable=SC2086
  exec agent-custody portal $portal_args
fi
# ROLE=signer runs the signer instead of the log; the log then signs through AGENT_CUSTODY_SIGNER_URL.
if [ "${ROLE:-log}" = "signer" ]; then
  key_dir=$(dirname "$AGENT_CUSTODY_LOG_KEY"); key_name=$(basename "$AGENT_CUSTODY_LOG_KEY" .key)
  mkdir -p "$key_dir"
  [ -f "$AGENT_CUSTODY_LOG_KEY" ] || agent-custody keygen --dir "$key_dir" --name "$key_name" >&2
  echo "agent-custody signer: public key (give this to verifiers as --log-key, or let them fetch it from the log):" >&2
  cat "$key_dir/$key_name.pub" >&2
  # Retired public keys stay in the key document so heads they signed keep verifying: one .pub per file in
  # /data/keys/retired/. See deploy/RUNBOOK.md, "Rotating the signing key".
  retired_args=""
  for pub in /data/keys/retired/*.pub; do [ -e "$pub" ] && retired_args="$retired_args --retired-key $pub"; done
  # shellcheck disable=SC2086
  exec agent-custody signer --key "$AGENT_CUSTODY_LOG_KEY" --host 0.0.0.0 --port "${AGENT_CUSTODY_SIGNER_PORT:-8790}" --token-env SIGNER_TOKEN $retired_args
fi
if [ -n "${AGENT_CUSTODY_SIGNER_URL:-}" ]; then
  log_id_args="$log_id_args --signer-url $AGENT_CUSTODY_SIGNER_URL --signer-token-env SIGNER_TOKEN"
  key_arg=""
else
  key_arg="--key $AGENT_CUSTODY_LOG_KEY"
fi

mkdir -p "$(dirname "$AGENT_CUSTODY_LOG_FILE")"
if [ -n "$key_arg" ]; then
  key_dir=$(dirname "$AGENT_CUSTODY_LOG_KEY"); key_name=$(basename "$AGENT_CUSTODY_LOG_KEY" .key)
  mkdir -p "$key_dir"
  if [ ! -f "$AGENT_CUSTODY_LOG_KEY" ]; then
    echo "agent-custody log: no signing key at $AGENT_CUSTODY_LOG_KEY; generating one" >&2
    agent-custody keygen --dir "$key_dir" --name "$key_name" >&2
  fi
  echo "agent-custody log: public key (verifiers fetch it from /.well-known/agent-custody-log.json):" >&2
  cat "$key_dir/$key_name.pub" >&2
fi

if [ -n "${AGENT_CUSTODY_LOG_TOKEN:-}" ]; then
  exec agent-custody log --file "$AGENT_CUSTODY_LOG_FILE" $key_arg --host 0.0.0.0 --port "$AGENT_CUSTODY_LOG_PORT" --token-env AGENT_CUSTODY_LOG_TOKEN $log_id_args
else
  echo "agent-custody log: WARNING no AGENT_CUSTODY_LOG_TOKEN set; anyone who can reach port $AGENT_CUSTODY_LOG_PORT may append" >&2
  exec agent-custody log --file "$AGENT_CUSTODY_LOG_FILE" $key_arg --host 0.0.0.0 --port "$AGENT_CUSTODY_LOG_PORT" $log_id_args
fi
