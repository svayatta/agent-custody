#!/bin/sh
# The founder's note to new registrations, once each, about an hour after they sign up. Runs inside the portal
# container against the same database and mail settings the portal uses. It reads .env from its own directory, so it
# must run in place: install a wrapper as /etc/cron.hourly/agent-custody-followup that execs this file (see the runbook),
# not a copy. Prints one line per run; a provider failure leaves the person pending for the next hour.
# MAIL_SIGNER and MAIL_SIGNER_ROLE in .env name who signs the note; the default is "The agent-custody team". With a signer, the note is in the first person.
set -eu
cd "$(dirname "$0")"
MAIL_FROM=$(sed -n 's/^MAIL_FROM=//p' .env | tail -1); MAIL_NOTIFY=$(sed -n 's/^MAIL_NOTIFY=//p' .env | tail -1); PORTAL_HOST=$(sed -n 's/^PORTAL_HOST=//p' .env | tail -1)
MAIL_REPLY_TO=$(sed -n 's/^MAIL_REPLY_TO=//p' .env | tail -1); MAIL_SIGNER=$(sed -n 's/^MAIL_SIGNER=//p' .env | tail -1); MAIL_SIGNER_ROLE=$(sed -n 's/^MAIL_SIGNER_ROLE=//p' .env | tail -1)
[ -n "$MAIL_FROM" ] || { echo "MAIL_FROM is not in .env; nothing sent"; exit 0; }
exec docker compose --profile public exec -T portal agent-custody portal-followup --db-env DATABASE_URL --secret-env PORTAL_SECRET --mail-key-env MAIL_API_KEY --mail-from "$MAIL_FROM" ${MAIL_NOTIFY:+--mail-notify "$MAIL_NOTIFY"} ${MAIL_REPLY_TO:+--mail-reply-to "$MAIL_REPLY_TO"} ${MAIL_SIGNER:+--signer "$MAIL_SIGNER"} ${MAIL_SIGNER_ROLE:+--signer-role "$MAIL_SIGNER_ROLE"} --portal-url "https://${PORTAL_HOST:-app.agent-custody.dev}/" "$@"
