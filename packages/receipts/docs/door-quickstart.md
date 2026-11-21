# Put the door in front of a site

This page is for someone who runs a website or an API. In about fifteen minutes you run the door in front of a small stand-in site, write one policy for a sign-up form, and watch four arrivals: a bot that is refused and told how to pass the challenge, a bot that only claims to be an agent, a person who passes the challenge, and an agent that shows a passport. Then you verify the receipts with public keys only.

You need Docker and `curl`. No Docker? Node 22 or later does the same: read [Without Docker](#without-docker) first. The person in step 6 passes Cloudflare Turnstile with its public test keys, which needs no account but does call Cloudflare once. Everything else runs on your machine.

The door runs from the gateway's container image. The same image runs every other `agent-custody` command on this page, so nothing is installed:

```bash
mkdir door-quickstart && cd door-quickstart
IMAGE=ghcr.io/svayatta/agent-custody-gateway:0.16.10
alias agent-custody='docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work -e TURNSTILE_SECRET $IMAGE'
```

Stay in this directory and this terminal for the whole page: the commands write their files here, and the later steps use the variables that the earlier steps set.

## 1. Keys

The door signs every receipt with its own key. The principal key belongs to whoever vouches for an agent: it signs the agent's passport, and the door trusts the passports it signs.

```bash
agent-custody keygen --dir keys --name door
agent-custody keygen --dir keys --name principal
```

## 2. A stand-in site

Your real site goes here later. This one answers a page on `GET /` and accepts a sign-up on `POST /form`. It runs in a container named `site`, on a network that only the door shares, so the door is the only way in:

```bash
docker network create door-quickstart
docker run -d --name site --network door-quickstart --entrypoint node $IMAGE -e 'require("http").createServer((q,s)=>{s.setHeader("content-type","text/plain");s.end(q.method==="GET"?"the sign-up page\n":"thanks, you are signed up\n")}).listen(3000)'
```

## 3. The policy

The door names each request by the route it falls under, and the policy decides per route. Anything the policy does not permit is refused. `policy.cedar`:

```cedar
// The page is public.
permit(principal, action == Action::"page", resource);

// The form takes a person who has passed the challenge...
permit(principal, action == Action::"form", resource)
when { context.facts.arrival.challenge.outcome == "passed" };

// ...or an agent whose passport covers the form.
permit(principal, action == Action::"form", resource)
when { context.facts.arrival.class == "verified" };
```

## 4. The door's config

`door.json`:

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://site:3000" },
  "routes": [
    { "name": "page", "methods": ["GET"], "path": "/" },
    { "name": "form", "methods": ["POST"], "path": "/form" }
  ],
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl",
  "challenge": {
    "provider": "turnstile",
    "siteKey": "1x00000000000000000000AA",
    "secretEnv": "TURNSTILE_SECRET",
    "hostnames": ["example.com"]
  }
}
```

`1x00000000000000000000AA` and the secret below are Cloudflare's [test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/): every token passes, and the answer names the host `example.com`. Check the config before you start the door:

```bash
export TURNSTILE_SECRET=1x0000000000000000000000000000000AA
agent-custody check --config door.json
```

```text
warn  origin: http://site:3000 is plain HTTP to a remote host; the relayed traffic is not encrypted on that leg
warn  revokedGrants: no revokedGrants file: a grant cannot be revoked at this door before it expires

no errors, 2 warnings
```

The last line must say `no errors`. The two warnings are correct for this page: the stand-in site is on a private network on your machine, and this page revokes no grant.

## 5. Start the door

```bash
docker run -d --name door --network door-quickstart --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work \
  -e TURNSTILE_SECRET -e DOOR_CONFIG=door.json -e DOOR_KEY=keys/door.key -p 127.0.0.1:8780:8780 $IMAGE door
curl -s http://127.0.0.1:8780/
```

```text
the sign-up page
```

The page went through the door, so it already has a receipt. If `curl` cannot connect, wait a second and try again. If it still cannot, `docker logs door` shows why the door did not start.

## 6. Four arrivals at the form

**A bot.** It presents nothing. The policy refuses it, and the 403 says how to pass the challenge, so your page can show the widget and try again:

```bash
curl -si -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' -d '{"email":"a@example.com"}' | tee bot.txt
```

```text
HTTP/1.1 403 Forbidden
x-agent-custody-receipt: 454a8bef-8044-4cc7-9806-b421918507d2
x-agent-custody-class: unknown

{"error":"refused by the door's policy","reason":"no permit policy matched","receipt":"454a8bef-8044-4cc7-9806-b421918507d2","challenge":{"provider":"turnstile","siteKey":"1x00000000000000000000AA","header":"x-agent-custody-challenge"}}
```

**A bot that says it is an agent.** A name in a header is a claim, and the door records it as one: the class is `claimed`, and no permit reads a claim:

```bash
curl -si -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' -H 'x-agent-custody-agent: shopping-agent' -d '{"email":"a@example.com"}'
```

```text
HTTP/1.1 403 Forbidden
x-agent-custody-class: claimed
```

**A person.** On a real page the Turnstile widget produces a token, and the page sends it in `x-agent-custody-challenge`. The door asks Cloudflare whether it is good. With the test secret any token passes:

```bash
curl -si -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' -H 'x-agent-custody-challenge: XXXX.DUMMY.TOKEN.XXXX' -d '{"email":"a@example.com"}'
```

```text
HTTP/1.1 200 OK
x-agent-custody-class: unknown

thanks, you are signed up
```

The class stays `unknown`: a passed challenge says the arrival solved a challenge, not who it is.

**An agent with a passport.** The principal signs a grant that names the agent and the routes it may use. The agent sends it, base64url-encoded, in `x-agent-custody-grant` (or as `Authorization: Bearer`):

```bash
agent-custody grant --key keys/principal.key --principal agent-co --agent shopping-agent --scopes form --out grant.json
PASSPORT=$(base64 < grant.json | tr -d '\n=' | tr '+/' '-_')
curl -si -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' -H "x-agent-custody-grant: $PASSPORT" -d '{"email":"agent@example.com"}' | tee agent.txt
```

```text
HTTP/1.1 200 OK
x-agent-custody-receipt: 3e30a694-f144-4b78-9b57-a906c8777803
x-agent-custody-class: verified

thanks, you are signed up
```

## 7. Verify the receipts

Every arrival left a receipt in `receipts/`, refused or not, and every one is in the log. A sign-up has two: the door commits it to the log before your site hears of it, then receipts the outcome. Each answer carries its receipt id in the `x-agent-custody-receipt` header. Step 6 saved two answers, so read the two ids from them:

```bash
BOT=$(tr -d '\r' < bot.txt | awk 'tolower($1)=="x-agent-custody-receipt:"{print $2}')
AGENT=$(tr -d '\r' < agent.txt | awk 'tolower($1)=="x-agent-custody-receipt:"{print $2}')
echo "$BOT $AGENT"
```

The refused bot, checked with the door's public key and the log:

```bash
agent-custody verify receipts/$BOT.json --issuer-key keys/door.pub --log log.jsonl
```

```text
PASS  policy decision consistent with execution  (deny -> denied)
PASS  log inclusion proof  (leaf 2 of 3, root c1b6db0a0f60)

RESULT: VERIFIED

ISSUER: door (http), enforced in front of the business's own HTTP surface; the arriving party could not forge this receipt and is attested only when it presented a grant, and a request that reached the origin some other way leaves no receipt
```

The agent, with the principal's key as well, so the passport is checked too:

```bash
agent-custody verify receipts/$AGENT.json --issuer-key keys/door.pub --principal-key keys/principal.pub --log log.jsonl
```

```text
PASS  delegation signature (principal key)  (signed by 9ebc1bcd4701)
PASS  executed tool within delegated scope  (form)
PASS  authorization logged before execution  (authorization leaf 6, receipt leaf 7)

RESULT: VERIFIED

principal       attested    agent-co
agent           attested    shopping-agent
policy          observed    allow [policy2] policy fbb0e37266c4
```

The output above is cut to the lines that matter; the full report lists every check, and your ids, digests, and leaf numbers differ. The request body is not in either receipt, only its digest: the door withholds by default ([what a receipt records](door.md#what-a-receipt-records-of-the-query-and-the-body)).

Stop the door and the stand-in site, and remove their network:

```bash
docker rm -f door site && docker network rm door-quickstart
```

## Without Docker

With Node 22 or later, the same page runs the CLI from npm. Four steps change, and every other command stays as it is:

- **The setup.** The alias is `alias agent-custody='npx -y -p @agent-custody/receipts@0.16.10 agent-custody'`, and there is no `IMAGE`.
- **Step 2.** Start the stand-in site with `node -e 'require("http").createServer((q,s)=>{s.setHeader("content-type","text/plain");s.end(q.method==="GET"?"the sign-up page\n":"thanks, you are signed up\n")}).listen(3000,"127.0.0.1")' &`.
- **Step 4.** In `door.json`, the origin is `"http://127.0.0.1:3000"`. The check then gives one warning, not two.
- **Step 5.** Start the door with `agent-custody door --config door.json --port 8780 &`.

At the end, stop both with `kill %1 %2`.

## Before you put it in front of your own site

- **Use your own Turnstile keys.** Put the widget on the page that posts the form, set `siteKey`, the secret in `TURNSTILE_SECRET`, and `hostnames` to your site's hosts. A token serves one request, so the page takes a new one for each submit ([challenging a human](door.md#what-the-door-knows-about-an-arrival)).
- **Make the door the only way in.** A request that reaches your site some other way leaves no receipt. Bind the site to a private address, or have it require a header that only the door adds (`origin.headerEnv`).
- **Run it as a service.** [deploy/door](../../../deploy/door/README.md) has a compose file, Kubernetes manifests, and a systemd unit for the same image, and the configs for a door behind your own nginx or Envoy.
- **Behind your own TLS proxy,** set `trustProxy` so the door reads the client's address, not the proxy's.
- **A passport alone is bearer-grade.** The door checks its signature, window, and scope, not that the sender holds the agent's key. Keep the time to live short. An agent that also signs its requests per Web Bot Auth, with `webBotAuth` configured, binds the passport to itself: see [Web Bot Auth signatures](door.md#web-bot-auth-signatures).
- **Read [the door](door.md)** for every field of the config, and [door signals](door-signals.md) for what each fact about an arrival does and does not establish, before you write a policy for a route that matters.
