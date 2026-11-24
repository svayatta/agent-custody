# The door as a WordPress plugin

> For a small business with a WordPress site. How the door works is in [the door](door.md). The plugin, its build script, and its smoke test are in [deploy/door/wordpress](../../../deploy/door/wordpress/README.md).

A WordPress site on ordinary hosting cannot run the Node door, and it has no proxy to put the door in. So the plugin is a door written in PHP. It decides each comment and each form submission inside WordPress, before WordPress acts on it. It signs a receipt for each decision with a key that stays on the site, and it appends the hash of each receipt to a log. The receipt is a door receipt: issuer kind `door`, framework `wordpress`. `agent-custody verify` checks it with the plugin's public key and the log, as it checks a receipt from any door.

The owner does three things: install the zip, connect the plugin to a log, and choose a policy preset.

## Install

1. Build the zip: `deploy/door/wordpress/build.sh` writes `agent-custody-door.zip`.
2. In WordPress, go to **Plugins > Add New > Upload Plugin**. Upload the zip and activate the plugin.
3. Go to **Settings > Agent Custody Door**.

On activation the plugin makes its signing key and a table for its receipts. It protects nothing until it is connected to a log, and it shows a notice until then.

The plugin needs WordPress 6.0 or later and PHP 7.4 or later. It has no other dependency: WordPress supplies the Ed25519 functions where PHP does not.

## Connect to the log

| setting | value |
| --- | --- |
| Log URL | the URL of your tenant on the hosted log, `https://log.agent-custody.dev/t/YOUR-TENANT/`, or the URL of any agent-custody log |
| Log token | the token of the tenant. To keep it out of the database, put `define( 'AGENT_CUSTODY_DOOR_LOG_TOKEN', '...' );` in `wp-config.php` |

When you save, the plugin reads the log's key document (`/.well-known/agent-custody-log.json`) and pins the keys. The page then shows `Connected` and the first 12 characters of each pinned key id. Compare them with the key ids that the log's operator publishes. A log at a new URL is a new log: the plugin reads and pins its keys again.

The log gets the hash of each receipt, never the receipt. The receipts stay in the site's database.

## Choose a preset

A preset is a Cedar policy text that the plugin ships. PHP has no Cedar engine, so the plugin decides each text in PHP, and the test suite checks each PHP decision against Cedar. The receipt records the digest of the policy text.

| preset | who may send a protected form | refuses |
| --- | --- | --- |
| **Watch** | all. The plugin records what Humans decides | nothing. Start here, and read the decisions |
| **Humans** | a visitor who passed the challenge, and a signed-in user | a submission without a passed challenge from a visitor who is not signed in |
| **Strict** | a visitor or a signed-in user who passed the challenge | each submission without a passed challenge |

Humans and Strict need a challenge. Make a widget at Cloudflare Turnstile or hCaptcha and enter its site key and its secret. To keep the secret out of the database, put `define( 'AGENT_CUSTODY_DOOR_CHALLENGE_SECRET', '...' );` in `wp-config.php`. Without a site key and a secret, no submission can pass a challenge: Humans then admits signed-in users only, and Strict admits nobody.

**Challenge hostnames** are the hostnames of the pages that show the widget. Empty means the hostname of the site. A token from a page on another hostname fails.

## What it protects

| form | the request | route in the receipt |
| --- | --- | --- |
| Comments | `POST /wp-comments-post.php` | `comment` |
| Login | `POST /wp-login.php` | `login` |
| Registration | `POST /wp-login.php?action=register` | `register` |
| Lost password | `POST /wp-login.php?action=lostpassword` | `lostpassword` |
| More protected paths | a `POST` to a path in the list, exact or with `/*` at the end | `form` |

Each stock form has a checkbox. The plugin puts the challenge widget in each protected stock form. **More protected paths** is for the forms of other plugins, for example `/wp-json/contact-form-7/*`. With a path in the list, the plugin also puts the widget in each form on a page that posts to the site, so the token goes with the form's fields. A client that is not a browser sends the token in the `X-Agent-Custody-Challenge` header.

## What happens to a submission

1. The plugin reads the challenge token and asks the provider if it is good. The outcome is `passed`, `failed`, `unavailable`, or `absent`.
2. It records the arrival fact: the class (`unknown`, or `claimed` when the request names an agent or presents a grant, a signature, or a passport), the address, the method, the path, the route, and the challenge outcome. It records a second fact, `wordpress`, with `loggedIn`.
3. The preset decides.
4. **Refused:** the visitor gets a 403 page with the receipt id. The plugin signs the receipt (`denied`) and appends it to the log after the answer.
5. **Allowed:** the plugin signs an authorization and commits it to the log. Only then does WordPress get the request. When WordPress has answered, the plugin signs the receipt, with the authorization and the status that WordPress answered (`executed`, or `failed` for a 5xx), and appends it to the log.

Each answer has `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class`.

**When the log does not answer.** A submission that the preset allows is not passed to WordPress: the visitor gets a 503, and the receipt says `withheld`. The evidence must exist before the effect. In Watch, the submission goes on without the authorization, and the PHP error log says so. A receipt that the log did not take stays in the database as `pending`. WordPress cron appends pending receipts each hour, the oldest first.

**When the door locks you out.** A wrong challenge key or a log that is down also stops your own login under Humans or Strict. Put `define( 'AGENT_CUSTODY_DOOR_OFF', true );` in `wp-config.php`. The plugin then decides nothing. Correct the settings and remove the line.

## Verify a receipt

The settings page lists the last 20 decisions. Each receipt id is a link to its bundle. The page also shows the door's public key: save it as `door.pub`.

```bash
npx agent-custody verify RECEIPT.json --issuer-key door.pub --log-url https://log.agent-custody.dev/t/YOUR-TENANT/
```

## What a receipt records

- `request.args`: the method, the path, and the `User-Agent`, `Content-Type`, `Accept`, and `Host` headers. No query, no body, and no digest of the body.
- `facts.arrival`: as above. The address is `REMOTE_ADDR`. Behind a proxy or a CDN it is the proxy's address.
- `facts.wordpress`: `{ "loggedIn": true | false }`. It does not name the user.
- `policy`: the decision, the rules that permitted it, and the digest of the preset's policy text. In Watch, `enforced` is `false`.
- `execution`: `denied`, `withheld`, or `executed` / `failed` with the HTTP status that WordPress answered.

The receipts hold the address and the `User-Agent` of each arrival. They are in the site's database, in the table `wp_agent_custody_receipts`. Receipts that are in the log are deleted after 90 days (filter `agent_custody_door_retention_days`). The plugin keeps its key and its receipts when it is deactivated or deleted: they are the evidence.

## What it does not do

- **Admit an agent.** The plugin checks no grant, no Web Bot Auth signature, and no registry passport. An arrival that presents one is `claimed`, never `verified`, and the presets admit it only if it passes the challenge. A site that must admit registered agents runs the Node door in front of WordPress ([the door](door.md)).
- **Run your own Cedar policy.** The three presets are the policies.
- **Record the rate, behaviour, or fingerprint signals** of the Node door.
- **Protect a path it does not see.** XML-RPC (`xmlrpc.php`) and application passwords sign in without the login form. With plain permalinks the REST route is in the query, and the path list matches paths only.
- **Give one token to two requests.** A provider accepts a token once. A form of another plugin that sends twice (a validation error, then a second try) needs a new token for the second try, and the widget makes one only when the page resets it.
- **Stay fast under a flood.** Each refused submission is one database row and one request to the log, made after the answer. The hourly flush sends 50 pending receipts.
- **Work across a multisite network.** Activate it on each site.

## What was checked, and how

- `test/door-wordpress.test.ts` runs the plugin's door class with the PHP command line: canonical JSON and digests equal to `crypto.ts`; the key id equal to the verifier's; each preset against Cedar for each challenge outcome, signed in and not; an allowed comment with its authorization and a refused one, each through a real log and through `verifyBundle` with no failed check; nine log answers that must be refused; the challenge outcomes; the routes. It makes no network request. A machine without `php` skips it.
- `deploy/door/wordpress/smoke.sh` runs a stock WordPress container with MariaDB and a hash-only log. It installs the plugin from its zip, connects it through the settings form, and checks that the comment form and the login form show the widget, that a comment and a login without a token get 403, that both pass with a token (Turnstile's public test keys), that a comment gets 503 while the log is down, and that all five receipts verify with `agent-custody verify`. Run by hand on WordPress 7.1.5 with PHP 8.3; it is not in CI.
- Not checked: hCaptcha against its real service, the widget in a browser, a form of another plugin on a protected path, and WordPress on PHP 7.4 (the door class passes its tests on PHP 7.4).
