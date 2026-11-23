# The run kit for issue 432

This directory is temporary. It does the real deployment that issue 432 asks for. Remove it before the pull request merges.

`run.sh` deploys the door Worker from this repository and a test origin to your Cloudflare account. It sends one allowed and one refused request, gets both receipts from R2, and verifies them against the hosted log. It stops at the first failure and prints no secret.

## Before you start

- The Cloudflare account has R2 enabled and a workers.dev subdomain.
- A Cloudflare API token for that one account, with a short TTL:
  - Account › Workers Scripts › Edit
  - Account › Workers R2 Storage › Edit
  - Account › Account Settings › Read
  - Account › Workers Tail › Read. The CPU time comes from `wrangler tail`.
- A tenant on the hosted log made only for this run, and its API key.
- Node 22, `jq`, and `curl`.

## Run

Put the Cloudflare token in one file and the tenant API key in a second file. Keep both files outside the repository.

```bash
bun install
bun run build
CF_TOKEN_FILE=<path> LOG_TOKEN_FILE=<path> TENANT=<tenant> deploy/door/cloudflare-worker/run-432/run.sh
```

The working tree must be clean, because the run uses the template as committed. The comment at the top of `run.sh` lists the optional inputs.

The script makes the door key on the first run. The key and all output go to `~/.cache/door-worker-run-432/`, outside the repository. Set `WORK` to use a different directory.

## What the script does that the template does not

- The test origin is a second Worker, `door-origin-test`, in the same account. It writes each request to the R2 bucket `door-origin-test-hits`. That list proves that the refused request does not reach the origin.
- The script adds the compatibility flag `global_fetch_strictly_public` to the door. Cloudflare says that a Worker needs this flag to fetch a second Worker on the same zone (error 1042). It is not confirmed that this applies to workers.dev. Run with `STRICT_PUBLIC=0` to deploy with the template's flags only, and report the result.
- The run's values go to `wrangler deploy` as `--var` flags. The tracked `wrangler.toml` does not change.

## Send back

Send the directory `out/<UTC time>/` of the successful run, or push it to this branch. Do not send `keys/door.key`.

Read the output first. The receipts and the tail hold your public IP address in `facts.arrival.remote`, and the tail holds your workers.dev host name. Say if these must not be published.

Also report the Workers plan of the account from the dashboard. The script can read the plan only if the token has Billing Read.

## Afterwards

Delete the two Workers (`agent-custody-door`, `door-origin-test`) and the two buckets (`agent-custody-door-receipts`, `door-origin-test-hits`) if you do not need them. Delete the Cloudflare token. Revoke the tenant's API key.
