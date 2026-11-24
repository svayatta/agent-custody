#!/bin/sh
# Smoke test for the WordPress plugin on a stock WordPress site (docker-compose.yaml): the plugin installs from its zip,
# the owner connects it to a hash-only log and chooses the Humans preset in the settings page, the comment form and the
# login form show the challenge, a comment and a login without the challenge are refused (403), a comment and a login
# with it are accepted, a login with an action that wp-login.php does not know is refused, a Contact Form 7 form on an
# extra path is refused without the challenge by each way to it and accepted with it, a login in Watch goes on, a comment while the log is down is not accepted
# (503) and its receipt goes to the log when the log is back, a refused comment while the queue is full gets no
# receipt, and every receipt verifies with the door's public key and the log's public key.
# The challenge uses Cloudflare Turnstile's public test keys, so the site calls Cloudflare. Contact Form 7 comes from
# wordpress.org.
# Usage: ./smoke.sh <agent-custody gateway image>   needs docker with compose, curl, zip, and a free port 18080
# SMOKE_KEEP=1 leaves the site up at the end, at http://localhost:18080 (owner / smoke-owner-pass), to try it by hand.
set -eu
image="${1:?usage: smoke.sh <name>:<tag>}"
here=$(cd "$(dirname "$0")" && pwd)
port=18080
site="http://localhost:$port"
work=$(mktemp -d)
chmod 777 "$work"
project="door-wordpress-smoke-$$"
compose() {
  AGENT_CUSTODY_IMAGE="$image" SMOKE_WORK="$work" SMOKE_UID="$(id -u)" SMOKE_GID="$(id -g)" LOG_TOKEN=smoke-log-token WORDPRESS_PORT="$port" \
    docker compose -f "$here/docker-compose.yaml" -p "$project" "$@"
}
cleanup() { [ -z "${SMOKE_KEEP:-}" ] || { echo "smoke: the site stays up; stop it with: docker compose -p $project --profile cli down -v" >&2; return; }; compose --profile cli down -v --remove-orphans > /dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "smoke: $*" >&2; compose logs --tail 40 wordpress log >&2 2>&1 || true; exit 1; }
cli() { docker run --rm -u "$(id -u):$(id -g)" -v "$work:/work" "$image" "$@"; }
wp() { compose --profile cli run --rm -T cli wp "$@"; }
# status and headers of a POST, in $work/answer
post() { curl -s -o /dev/null -D "$work/answer" "$@"; }
status() { sed -n '1s/^[^ ]* \([0-9]*\).*/\1/p' "$work/answer"; }
receipt() { tr -d '\r' < "$work/answer" | sed -n 's/^[Xx]-[Aa]gent-[Cc]ustody-[Rr]eceipt: //p'; }
comments() { wp comment list --post_id=1 --format=count; }
token=XXXX.DUMMY.TOKEN.XXXX

mkdir -p "$work/keys" "$work/log" "$work/receipts"
# WP-CLI runs as www-data in its container and writes the receipts here.
chmod 777 "$work/receipts"
"$here/build.sh" "$work" > /dev/null || fail "build.sh failed"
chmod 644 "$work/agent-custody-door.zip"
cli keygen --dir /work/keys --name log > /dev/null 2>&1 || fail "keygen failed"

compose up -d --quiet-pull > /dev/null 2>&1 || fail "docker compose up failed"
i=0
until curl -s -o /dev/null "$site/wp-login.php"; do i=$((i + 1)); [ "$i" -lt 60 ] || fail "WordPress did not start"; sleep 2; done
wp core install --url="$site" --title=Smoke --admin_user=owner --admin_password=smoke-owner-pass --admin_email=owner@example.com --skip-email > /dev/null || fail "wp core install failed"
wp plugin install /work/agent-custody-door.zip --activate > /dev/null 2>&1 || fail "the plugin did not install from its zip"
wp rewrite structure '/%postname%/' > /dev/null 2>&1 || fail "the permalinks did not change"
wp plugin install contact-form-7 --activate > /dev/null 2>&1 || fail "Contact Form 7 did not install"
form=$(wp post list --post_type=wpcf7_contact_form --field=ID | head -1)
[ -n "$form" ] || fail "Contact Form 7 made no form"
wp post create --post_type=page --post_status=publish --post_name=contact --post_title=Contact --post_content="[contact-form-7 id=\"$form\"]" > /dev/null || fail "the contact page was not made"
feedback="$site/wp-json/contact-form-7/v1/contact-forms/$form/feedback"
contact() { post "$feedback" -F "_wpcf7=$form" -F "_wpcf7_unit_tag=wpcf7-f$form-o1" -F your-name=Person -F your-email=person@example.com -F your-subject=Hello -F your-message=Hello "$@"; }
before=$(comments)

# Not connected: the door protects nothing, and a comment goes through as on any WordPress site.
post "$site/wp-comments-post.php" -d comment_post_ID=1 -d author=Early -d email=early@example.com -d comment="before the door"
[ "$(status)" = 302 ] || fail "a comment before the door was connected got $(status), want 302"
[ -z "$(receipt)" ] || fail "a door that is not connected wrote a receipt"

# The owner signs in and saves the settings form: the log, the preset, and Turnstile's test keys.
jar="$work/cookies"
curl -s -o /dev/null -c "$jar" -d log=owner -d pwd=smoke-owner-pass "$site/wp-login.php"
nonce=$(curl -s -b "$jar" "$site/wp-admin/options-general.php?page=agent-custody-door" | sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$nonce" ] || fail "the settings page did not load"
curl -s -o /dev/null -b "$jar" "$site/wp-admin/options.php" -d option_page=agent_custody_door -d action=update -d _wpnonce="$nonce" \
  --data-urlencode "_wp_http_referer=/wp-admin/options-general.php?page=agent-custody-door" \
  --data-urlencode "agent_custody_door[log_url]=http://log:8787/" -d "agent_custody_door[log_token]=smoke-log-token" \
  -d "agent_custody_door[preset]=humans" -d "agent_custody_door[provider]=turnstile" -d "agent_custody_door[site_key]=1x00000000000000000000AA" \
  -d "agent_custody_door[secret]=1x0000000000000000000000000000000AA" -d "agent_custody_door[hostnames]=example.com" \
  --data-urlencode "agent_custody_door[paths]=/wp-json/contact-form-7/*" \
  -d "agent_custody_door[protect][]=comment" -d "agent_custody_door[protect][]=login" -d "agent_custody_door[protect][]=register" -d "agent_custody_door[protect][]=lostpassword"
wp option get agent_custody_door --format=json | grep -q '"log_keys":{"' || fail "the settings form did not connect the door to the log"

curl -sL "$site/?p=1" | grep -q 'class="cf-turnstile" data-sitekey="1x00000000000000000000AA"' || fail "the comment form has no challenge"
curl -s "$site/wp-login.php" | grep -q 'class="cf-turnstile"' || fail "the login form has no challenge"
curl -s "$site/contact/" | grep -q 'cf-turnstile.*data-sitekey' || fail "the contact page has no challenge script"

post "$site/wp-comments-post.php" -d comment_post_ID=1 -d author=Bot -d email=bot@example.com -d comment="a bot's comment"
[ "$(status)" = 403 ] || fail "a comment without the challenge got $(status), want 403"
denied=$(receipt); [ -n "$denied" ] || fail "the refused comment has no receipt"

# WordPress itself refuses a second comment from one address within 15 seconds.
sleep 16
post "$site/wp-comments-post.php" -d comment_post_ID=1 -d author=Person -d email=person@example.com -d comment="a person's comment" -d "cf-turnstile-response=$token"
[ "$(status)" = 302 ] || fail "a comment with the challenge got $(status), want 302"
allowed=$(receipt); [ -n "$allowed" ] || fail "the accepted comment has no receipt"

post "$site/wp-login.php" -d log=owner -d pwd=smoke-owner-pass
[ "$(status)" = 403 ] || fail "a login without the challenge got $(status), want 403"
login_denied=$(receipt)
post "$site/wp-login.php" -d log=owner -d pwd=smoke-owner-pass -d "cf-turnstile-response=$token"
[ "$(status)" = 302 ] || fail "a login with the challenge got $(status), want 302"
login_allowed=$(receipt)
# wp-login.php signs in on an action that it does not know, so the door decides it as a login.
post "$site/wp-login.php?action=form" -d log=owner -d pwd=smoke-owner-pass
[ "$(status)" = 403 ] || fail "a login with an unknown action and without the challenge got $(status), want 403"
login_action=$(receipt)
# wp-login.php also takes a login from a sender who is signed in, so the owner's cookie does not replace the challenge.
post -b "$jar" "$site/wp-login.php" -d log=owner -d pwd=wrong
[ "$(status)" = 403 ] || fail "a login from a signed-in user without the challenge got $(status), want 403"
# The REST API also makes a comment. Without the door, WordPress answers 401 to a visitor here.
post "$site/wp-json/wp/v2/comments" -d post=1 -d content="a comment through the REST API"
[ "$(status)" = 403 ] || fail "a REST comment without the challenge got $(status), want 403"

contact
[ "$(status)" = 403 ] || fail "a contact form without the challenge got $(status), want 403"
contact_denied=$(receipt)
# The other ways to the same form: a second spelling of the path, the route in the query, and a GET that asks to run as a POST.
for way in "$site//WP-JSON/contact-form-7/v1/contact-forms/$form/feedback" "$site/?rest_route=/contact-form-7/v1/contact-forms/$form/feedback"; do
  post "$way" -F "_wpcf7=$form" -F your-name=Bot
  [ "$(status)" = 403 ] || fail "a contact form at $way without the challenge got $(status), want 403"
done
post -G "$feedback" -d _method=POST -d "_wpcf7=$form"
[ "$(status)" = 403 ] || fail "a GET with _method=POST to the contact form got $(status), want 403"
contact -F "cf-turnstile-response=$token"
[ "$(status)" = 200 ] || fail "a contact form with the challenge got $(status), want 200"
contact_allowed=$(receipt)

# A refused submission makes no request to the log: its receipt waits for the flush.
[ "$(wp eval 'echo acd_pending();')" = 9 ] || fail "want 9 refused receipts in the queue, got $(wp eval 'echo acd_pending();')"

# The log is down: the comment is not accepted, and its receipt waits.
compose stop log > /dev/null 2>&1
post "$site/wp-comments-post.php" -d comment_post_ID=1 -d author=Later -d email=later@example.com -d comment="while the log is down" -d "cf-turnstile-response=$token"
[ "$(status)" = 503 ] || fail "a comment while the log was down got $(status), want 503"
withheld=$(receipt)
[ "$(comments)" = "$((before + 2))" ] || fail "the post has $(comments) comments, want $((before + 2)): the one before the door and the one that passed the challenge"
# Watch: a login that Humans refuses goes on to WordPress, with no request to the log.
wp eval 'update_option( "agent_custody_door", array( "preset" => "watch" ) + get_option( "agent_custody_door" ) );'
post "$site/wp-login.php" -d log=owner -d pwd=wrong
[ "$(status)" = 200 ] || fail "a login in Watch got $(status), want 200 from WordPress"
watched=$(receipt); [ -n "$watched" ] || fail "the login in Watch has no receipt"
[ "$(wp eval 'echo acd_pending();')" = 10 ] || fail "the receipt of the login in Watch is not in the queue"
wp eval 'update_option( "agent_custody_door", array( "preset" => "humans" ) + get_option( "agent_custody_door" ) );'
# The queue is full: the door still refuses, and it signs no receipt.
wp eval 'wp_mkdir_p( WPMU_PLUGIN_DIR ); file_put_contents( WPMU_PLUGIN_DIR . "/full.php", "<?php add_filter( \"agent_custody_door_max_pending\", \"__return_zero\" );" );'
post "$site/wp-comments-post.php" -d comment_post_ID=1 -d author=Flood -d email=flood@example.com -d comment="one of many"
[ "$(status)" = 403 ] || fail "a comment while the queue was full got $(status), want 403"
wp eval 'unlink( WPMU_PLUGIN_DIR . "/full.php" );'
compose start log > /dev/null 2>&1
sleep 2
wp cron event run agent_custody_door_flush > /dev/null 2>&1 || fail "the flush did not run"

wp eval 'echo Agent_Custody_Door::public_pem( get_option( "agent_custody_door_key" ) );' > "$work/keys/door.pub"
# shellcheck disable=SC2016  # PHP variables, not shell ones
wp eval 'global $wpdb; foreach ( $wpdb->get_results( "SELECT receipt_id, status, bundle FROM " . acd_table() ) as $r ) { file_put_contents( "/work/receipts/" . $r->receipt_id . "." . $r->status . ".json", $r->bundle ); }'
for id in "$denied" "$allowed" "$login_denied" "$login_allowed" "$login_action" "$contact_denied" "$contact_allowed" "$watched" "$withheld"; do
  [ -f "$work/receipts/$id.logged.json" ] || fail "receipt $id is not logged: $(ls "$work/receipts")"
done
for file in "$work"/receipts/*.json; do
  name=$(basename "$file")
  case "$name" in *.logged.json) ;; *) fail "receipt $name is not in the log" ;; esac
  cli verify "/work/receipts/$name" --issuer-key /work/keys/door.pub --log-key /work/keys/log.pub > "$work/verify.txt" 2>&1 || { cat "$work/verify.txt" >&2; fail "receipt $name did not verify"; }
done
[ "$(find "$work/receipts" -type f | wc -l | tr -d ' ')" = 14 ] || fail "want 14 receipts, got: $(ls "$work/receipts")"
echo "smoke: OK (the plugin installed from its zip; 14 receipts verified, with: comment $denied denied and $allowed executed, login $login_denied and $login_action denied and $login_allowed executed, contact form $contact_denied denied and $contact_allowed executed, $watched in Watch, $withheld withheld)"
