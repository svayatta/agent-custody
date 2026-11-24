# The door as a WordPress plugin

> For a small business with a WordPress site. How the door works is in [the door](door.md). The plugin, its build script, and its smoke test are in [deploy/door/wordpress](../../../deploy/door/wordpress/README.md).

A WordPress site on ordinary hosting cannot run the Node door, and it has no proxy to put the door in. So the plugin is a door written in PHP. It decides each comment and each form submission inside WordPress, before WordPress acts on it. It signs a receipt for each decision with a key that stays on the site, and it appends the hash of each receipt to a log. The receipt is a door receipt: issuer kind `door`, framework `wordpress`. `agent-custody verify` checks it with the plugin's public key and the log, as it checks a receipt from any door.

The owner does three things: install the zip, connect the plugin to a log, and choose a policy preset.

## Install

No release publishes the plugin, and a merge to `main` installs it on no site. You build the zip from the repository and upload it.

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
| **Humans** | a visitor who passed the challenge, and a signed-in user on a comment or on one of the more protected paths | a submission without a passed challenge from a visitor who is not signed in; a login, a registration, or a lost password without a passed challenge from anyone |
| **Strict** | a visitor or a signed-in user who passed the challenge | each submission without a passed challenge |

Humans and Strict need a challenge. Make a widget at Cloudflare Turnstile or hCaptcha and enter its site key and its secret. To keep the secret out of the database, put `define( 'AGENT_CUSTODY_DOOR_CHALLENGE_SECRET', '...' );` in `wp-config.php`. Without a site key and a secret, no submission can pass a challenge and nobody can sign in, so the settings form does not take Humans or Strict without them: it keeps Watch and says why.

A signed-in user is exempt in Humans for comments and the more protected paths only. `wp-login.php` takes a login, a registration, or a lost password from a sender who is signed in already, so those forms always need the challenge. On a REST path (`/wp-json/...`), a sender is signed in only with the REST nonce, as for WordPress itself.

**Challenge hostnames** are the hostnames of the pages that show the widget. Empty means the hostname of the site, with and without `www.`. A token from a page on another hostname fails.

## Put it on a live site

Do the first install on a test site, not on the live one.

1. Install the plugin, connect it to the log, and keep Watch. Watch refuses nothing, so a wrong setting stops nobody.
2. Send a comment while you are signed in, then sign out and sign in. Look at **The last 20 decisions** on the settings page. The comment has the decision `allow` and must show `logged` in the Log column at once: the site reaches the log, and the token is good. The login has the decision `deny`, because no challenge is set yet, and shows `pending` until the hourly run sends it.
3. Download a receipt that shows `logged` from that table and verify it ([Verify a receipt](#verify-a-receipt)).
4. Enter the challenge keys and change the preset to Humans.
5. In a browser window that is not signed in, sign in and send a comment. Each form must show the widget, and each submission must pass.
6. Do the same steps on the live site. Leave Watch on for some days before you change to Humans, and read what Humans would refuse.

If step 5 fails and you cannot sign in, see "When the door locks you out".

## What it protects

| form | the request | route in the receipt |
| --- | --- | --- |
| Comments | `POST /wp-comments-post.php`, and a trackback (`/wp-trackback.php`) | `comment` |
| Login | `POST /wp-login.php`, with no `action` or with an `action` that WordPress does not know: WordPress signs in on each of them | `login` |
| Registration | `POST /wp-login.php?action=register`, and `/wp-signup.php` on a network | `register` |
| Lost password | `POST /wp-login.php?action=lostpassword` | `lostpassword` |
| More protected paths | a request to a path in the list, exact or with `/*` at the end | `form` |

Each stock form has a checkbox. The plugin puts the challenge widget in each protected stock form. **More protected paths** is for the forms of other plugins, for example `/wp-json/contact-form-7/*`. With a path in the list, the plugin also puts the widget in each form on a page that posts to the site, so the token goes with the form's fields. A client that is not a browser sends the token in the `X-Agent-Custody-Challenge` header.

The door decides each request that is not a `GET`, a `HEAD`, or an `OPTIONS`, and each request that asks the REST API for another method (`_method`, `X-HTTP-Method-Override`). A path in the list starts after the site's address: on a site at `https://example.com/blog/`, write `/wp-json/contact-form-7/*`. The door compares paths as WordPress and the web server read them, so these all match that entry: `//WP-JSON/Contact-Form-7/...`, `/index.php/wp-json/contact-form-7/...`, and `/?rest_route=/contact-form-7/...`. An exact entry also matches with a `/` at the end, and an entry for a script matches the script with a path after it.

## What happens to a submission

1. The plugin reads the challenge token and asks the provider if it is good. The outcome is `passed`, `failed`, `unavailable`, or `absent`.
2. It records the arrival fact: the class (`unknown`, or `claimed` when the request names an agent or presents a grant, a signature, or a passport), the address, the method, the path, the route, and the challenge outcome. It records a second fact, `wordpress`, with `loggedIn`.
3. The preset decides. In Watch, a submission that Humans does not allow goes on to WordPress. Like a refused submission, it makes no request to the log and gets no authorization, and its receipt waits for the flush.
4. **Refused:** the visitor gets a 403 page with the receipt id. The plugin signs the receipt (`denied`) and stores it as `pending`. It makes no request to the log for a refused submission: the hourly flush appends the receipt.
5. **Allowed:** the plugin signs an authorization and commits it to the log. Only then does WordPress get the request. When WordPress has answered, the plugin signs the receipt, with the authorization and the status that WordPress answered (`executed`, or `failed` for a 5xx), and appends it to the log.

Each answer has `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class`.

**When the log does not answer.** A submission that the preset allows is not passed to WordPress: the visitor gets a 503, and the receipt says `withheld`. The evidence must exist before the effect. In Watch, the submission goes on without the authorization, and the PHP error log says so. A receipt that the log did not take stays in the database as `pending`. WordPress cron appends pending receipts each hour: 50 in one run (filter `agent_custody_door_flush_batch`), the receipts of allowed submissions first, then the oldest first.

**When refused submissions flood the site.** A refused submission costs its sender nothing, so the plugin puts a bound on what it costs the site. It makes no request to the log, so refused submissions use at most 50 appends of the log's quota in an hour, and they cannot use up the quota that allowed submissions need. When 500 such receipts are `pending` (filter `agent_custody_door_max_pending`), the door still refuses each submission, and it signs no receipt for it until the flush makes room. Those refusals have no evidence.

**When the log has a new key.** The plugin pins the log's keys when it connects, and it refuses an answer that another key signed. To read the keys again, empty the log URL, save, enter the URL and the token, and save.

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

The receipts hold the address and the `User-Agent` of each arrival. They are in the site's database, in the table `wp_agent_custody_receipts`. The receipts that are in the log have two bounds. Such a receipt is deleted after 90 days (filter `agent_custody_door_retention_days`), and the hourly run keeps the newest 10,000 of them (filter `agent_custody_door_max_receipts`). A receipt that is not in the log yet is never deleted: the database has the only evidence of it. The receipt records at most 1,024 characters of the path and of each header. The log has only the hash of a receipt, so download a receipt that you must keep before it is deleted. The plugin keeps its key and its receipts when it is deactivated or deleted: they are the evidence.

## What it does not do

- **Admit an agent.** The plugin checks no grant, no Web Bot Auth signature, and no registry passport. An arrival that presents one is `claimed`, never `verified`, and the presets admit it only if it passes the challenge. A site that must admit registered agents runs the Node door in front of WordPress ([the door](door.md)).
- **Run your own Cedar policy.** The three presets are the policies.
- **Record the rate, behaviour, or fingerprint signals** of the Node door.
- **Protect a path it does not see.** XML-RPC (`xmlrpc.php`) signs in, makes comments, and takes pingbacks without the forms, and application passwords sign in without the login form. Put `/xmlrpc.php` in the path list to refuse them. A plugin that moves the login form to another address, or that reads a form before the WordPress `init` action, is not seen.
- **Put a bound on the challenge checks.** Each submission with a token is one request to the provider, and the visitor waits for it, 5 seconds at most. The Node door has a bound on the checks in flight; the plugin has none.
- **Give one token to two requests.** A provider accepts a token once. A form of another plugin that sends twice (a validation error, then a second try) needs a new token for the second try, and the widget makes one only when the page resets it.
- **Sign a receipt for each refusal in a flood.** See "When refused submissions flood the site". Each refused submission is still one request to the challenge provider when it has a token, and one database row until the queue is full.
- **Protect a post password.** The door does not decide `wp-login.php?action=postpass`.
- **Work across a multisite network.** Activate it on each site.

## What was checked, and how

- `test/door-wordpress.test.ts` runs the plugin's door class with the PHP command line: canonical JSON and digests equal to `crypto.ts`; the key id equal to the verifier's; each preset against Cedar for each challenge outcome and each route, signed in and not; an allowed comment with its authorization and a refused one, each through a real log and through `verifyBundle` with no failed check; nine log answers that must be refused; the challenge outcomes; the routes, with the spellings of a path that must match. It makes no network request. A machine without `php` skips it.
- `deploy/door/wordpress/smoke.sh` runs a stock WordPress container with MariaDB, Contact Form 7, and a hash-only log. It installs the plugin from its zip, connects it through the settings form, and checks that the comment form, the login form, and the contact page show the widget; that a comment, a login, and a contact form without a token get 403 and pass with a token (Turnstile's public test keys); that a login with an action that WordPress does not know gets 403; that three other ways to the contact form (a second spelling of the path, `rest_route` in the query, a `GET` with `_method=POST`) get 403; that a login from a signed-in user without a token gets 403; that a login in Watch goes on and its receipt waits; that a refused submission makes no request to the log; that a comment gets 503 while the log is down; that a refused comment gets no receipt while the queue is full; and that all thirteen receipts are in the log and verify with `agent-custody verify`. The `gateway-image` workflow runs it on each pull request that touches `deploy/door`. Last run on WordPress 7.1.5 with PHP 8.3.
- By hand, in a browser, on the smoke test's site: the Turnstile widget (test keys) shows in the comment form and in the Contact Form 7 form and makes a token, and a comment and a contact form that are sent from the page pass the door.
- Not checked: the hosted log at `log.agent-custody.dev` (the smoke test's log is the same server in one-tenant mode over plain HTTP), hCaptcha against its real service, a widget with real keys, the registration form and the lost-password form on a site, and WordPress on PHP 7.4 (the door class passes its tests on PHP 7.4).
