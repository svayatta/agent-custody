# The door as a WordPress plugin

The agent-custody door for a stock WordPress site: a plugin in PHP that decides each comment and form submission with a policy preset, signs a receipt of each decision, and appends the hash of each receipt to a log. The guide is [the door as a WordPress plugin](../../../packages/receipts/docs/door-wordpress.md): install, connect, presets, what a receipt records, and the limits.

| file | what it is |
| --- | --- |
| [agent-custody-door/](agent-custody-door) | the plugin. `agent-custody-door.php` has the WordPress hooks, the settings page, and the receipt table. `includes/class-agent-custody-door.php` is the door: it does not call WordPress |
| [build.sh](build.sh) | writes `agent-custody-door.zip`, the file a site owner uploads at **Plugins > Add New > Upload Plugin** |
| [harness.php](harness.php) | runs the door class from the PHP command line for `packages/receipts/test/door-wordpress.test.ts`. It is not in the zip |
| [docker-compose.yaml](docker-compose.yaml), [smoke.sh](smoke.sh) | a stock WordPress site with MariaDB and a hash-only log, and the smoke test that runs on it |

```bash
./build.sh                                                   # agent-custody-door.zip
./smoke.sh ghcr.io/svayatta/agent-custody-gateway:0.16.13    # needs docker with compose, curl, zip, and a free port 18080
```

The smoke test installs the plugin from its zip, connects it to the log through the settings form, and sends a comment and a login without the challenge (403) and with it (accepted), and a comment while the log is down (503). It then verifies all five receipts with `agent-custody verify`. The challenge uses Cloudflare Turnstile's public test keys, so the site calls Cloudflare. It ends with `smoke: OK`.

A change to the door class must pass `bun run test` on a machine with `php`. A change to the plugin must also pass `smoke.sh`, by hand: no workflow runs it.
