=== Agent Custody Door ===
Contributors: svayatta
Tags: comments, spam, captcha, login, security
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.0
License: Apache-2.0
License URI: https://www.apache.org/licenses/LICENSE-2.0

Protects comments and forms with a policy preset, and signs a receipt of each decision that anyone can verify.

== Description ==

The door decides each comment, login, registration, and lost-password request before WordPress acts on it. You choose a policy preset:

* Watch: record each decision and refuse nothing.
* Humans: a visitor must pass a Cloudflare Turnstile or hCaptcha challenge. A signed-in user needs no challenge.
* Strict: each submission must pass the challenge.

The door signs a receipt for each decision with a key that stays on your site, and appends the hash of the receipt to an agent-custody log. The receipt shows what arrived, what the policy decided, and what WordPress answered. A person with your public key can verify a receipt without trust in you or in the log's operator.

This plugin checks no agent credential. An arrival that presents a grant, a signature, or a passport is recorded as a claim.

== External services ==

* An agent-custody log, at the URL you enter (the hosted log is https://log.agent-custody.dev/). For each decision the plugin sends the SHA-256 hash of the signed receipt and your log token. It does not send the receipt.
* Cloudflare Turnstile (https://challenges.cloudflare.com/) or hCaptcha (https://hcaptcha.com/), when you enter a site key and a secret. The visitor's browser loads the provider's widget. The plugin sends the widget's token and your secret to the provider.

== Privacy ==

Each receipt holds the address and the User-Agent of the arrival, the form, and the decision. Receipts are in your site's database. A receipt is deleted after 90 days, and the table keeps the newest 10,000 receipts.

== Installation ==

1. Upload the zip at Plugins > Add New > Upload Plugin, and activate the plugin.
2. Go to Settings > Agent Custody Door.
3. Enter the URL and the token of your log, and save. The page shows "Connected".
4. Enter the site key and the secret of your challenge widget.
5. Start with the Watch preset. Read the decisions, then choose Humans or Strict.

If the door locks you out, put `define( 'AGENT_CUSTODY_DOOR_OFF', true );` in wp-config.php.

== Changelog ==

= 0.1.0 =
* The first version.
