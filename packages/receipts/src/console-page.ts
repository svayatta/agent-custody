// The console's one page. The data it shows is written into the document with textContent only, never as markup, and the
// content-security-policy allows exactly this script and this style by hash, so a value that reaches the page cannot run.
import { createHash } from "node:crypto";

const STYLE = String.raw`
:root { --bg: #fafaf9; --panel: #ffffff; --ink: #1c1917; --muted: #78716c; --line: #e7e5e4; --accent: #b45309; --accent-ink: #ffffff; --ok: #15803d; --warn: #b45309; --bad: #b91c1c; --code: #f5f5f4; color-scheme: light dark; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --bg: #1c1917; --panel: #292524; --ink: #fafaf9; --muted: #a8a29e; --line: #44403c; --accent: #f59e0b; --accent-ink: #1c1917; --ok: #4ade80; --warn: #fbbf24; --bad: #f87171; --code: #1c1917; } }
:root[data-theme="dark"] { --bg: #1c1917; --panel: #292524; --ink: #fafaf9; --muted: #a8a29e; --line: #44403c; --accent: #f59e0b; --accent-ink: #1c1917; --ok: #4ade80; --warn: #fbbf24; --bad: #f87171; --code: #1c1917; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.5 Inter, system-ui, -apple-system, "Segoe UI", sans-serif; }
header { display: flex; align-items: center; gap: 16px; padding: 12px 24px; border-bottom: 1px solid var(--line); background: var(--panel); flex-wrap: wrap; }
header h1 { font-size: 15px; margin: 0; font-weight: 650; }
nav { display: flex; gap: 4px; flex-wrap: wrap; flex: 1; }
nav button { background: none; border: 0; padding: 6px 12px; border-radius: 6px; color: var(--muted); cursor: pointer; font: inherit; }
nav button[aria-current="page"] { background: var(--code); color: var(--ink); font-weight: 600; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }
h2 { font-size: 18px; margin: 0 0 12px; }
h3 { font-size: 14px; margin: 0 0 8px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }
.grid .card { margin: 0; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
th { color: var(--muted); font-weight: 600; font-size: 12px; white-space: nowrap; overflow-wrap: normal; }
table.kv th { width: 9em; white-space: nowrap; overflow-wrap: normal; }
tr.click { cursor: pointer; } tr.click:hover { background: var(--code); }
code, pre, textarea { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; }
pre { background: var(--code); padding: 10px; border-radius: 6px; overflow: auto; max-height: 420px; margin: 8px 0 0; }
textarea { width: 100%; min-height: 280px; background: var(--code); color: var(--ink); border: 1px solid var(--line); border-radius: 6px; padding: 10px; resize: vertical; }
input[type=password], input[type=text], select { background: var(--code); color: var(--ink); border: 1px solid var(--line); border-radius: 6px; padding: 6px 10px; font: inherit; }
button.primary { background: var(--accent); color: var(--accent-ink); border: 0; border-radius: 6px; padding: 7px 14px; font: inherit; font-weight: 600; cursor: pointer; }
button.secondary { background: var(--panel); color: var(--ink); border: 1px solid var(--line); border-radius: 6px; padding: 7px 14px; font: inherit; cursor: pointer; }
button.danger { background: var(--bad); color: #fff; border: 0; border-radius: 6px; padding: 7px 14px; font: inherit; font-weight: 600; cursor: pointer; }
button:disabled { opacity: .5; cursor: default; }
.row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 8px 0; }
.muted { color: var(--muted); }
.ok { color: var(--ok); } .warn { color: var(--warn); } .error, .bad { color: var(--bad); }
.pill { display: inline-block; padding: 0 8px; border-radius: 999px; border: 1px solid var(--line); font-size: 12px; }
.banner { border: 1px solid var(--line); border-left: 4px solid var(--accent); background: var(--panel); border-radius: 6px; padding: 10px 14px; margin-bottom: 16px; }
.banner.bad { border-left-color: var(--bad); }
.finding { display: grid; grid-template-columns: 56px 130px 1fr; gap: 8px; padding: 4px 0; border-bottom: 1px solid var(--line); }
#login { max-width: 420px; margin: 96px auto; }
[hidden] { display: none !important; }
.mt { margin-top: 16px; }
textarea.short { min-height: 140px; }
@media (max-width: 600px) { .finding { grid-template-columns: 56px 1fr; } .finding .check { display: none; } }
`;

const SCRIPT = String.raw`
(function () {
  'use strict';
  var KEY = 'agent-custody-console-token';
  var THEME = 'agent-custody-theme';
  try { var t = localStorage.getItem(THEME); if (t) document.documentElement.setAttribute('data-theme', t); } catch (e) {}
  var token = '';
  try { token = sessionStorage.getItem(KEY) || ''; } catch (e) {}
  var view = document.getElementById('view');
  var tabs = ['Overview', 'Check', 'Policy', 'Grants', 'Receipts', 'Audit'];
  var current = 'Overview';
  var policyDigest = '';

  function h(tag, attrs) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, '');
      else if (v !== false && v != null) e.setAttribute(k, v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null || c === false) continue;
      e.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    }
    return e;
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }
  function say(text, bad) {
    var m = document.getElementById('msg');
    clear(m);
    if (text) m.appendChild(h('div', { class: 'banner' + (bad ? ' bad' : ''), role: bad ? 'alert' : 'status', text: text }));
  }
  function api(method, path, body) {
    return fetch(path, { method: method, headers: { 'authorization': 'Bearer ' + token, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
      .then(function (r) {
        return r.json().then(function (data) {
          if (r.status === 401 || r.status === 429) { signOut(); throw new Error(data.error || 'sign in again'); }
          if (!r.ok) throw new Error(data.error || ('request failed: ' + r.status));
          return data;
        });
      });
  }
  function fail(e) { say(e.message || String(e), true); }
  function signOut() {
    token = '';
    try { sessionStorage.removeItem(KEY); } catch (e) {}
    document.getElementById('app').hidden = true;
    document.getElementById('login').hidden = false;
  }
  function kv(rows) {
    var t = h('table', { class: 'kv' });
    rows.forEach(function (r) { t.appendChild(h('tr', null, h('th', { text: r[0] }), h('td', null, r[1] == null ? '-' : r[1]))); });
    return t;
  }
  function mark(level) { return h('span', { class: level, text: level === 'ok' ? 'ok' : level === 'warn' ? 'warn' : 'ERROR' }); }
  function findings(list) {
    var box = h('div');
    list.forEach(function (f) { box.appendChild(h('div', { class: 'finding' }, mark(f.level), h('span', { class: 'muted check', text: f.check }), h('span', { text: f.message }))); });
    return box;
  }
  function short(s) { return s ? String(s).slice(0, 12) + '…' : '-'; }

  var renderers = {
    Overview: function () {
      return api('GET', '/api/overview').then(function (o) {
        var g = o.gateway;
        var gw = g == null ? h('span', { class: 'muted', text: 'not configured (start the console with --gateway-url)' })
          : g.reachable ? h('span', { class: 'ok', text: 'running, ' + g.sessions + ' open session' + (g.sessions === 1 ? '' : 's') }) : h('span', { class: 'bad', text: 'not reachable' + (g.error ? ': ' + g.error : '') });
        var up = h('table', null, h('tr', null, h('th', { text: 'name' }), h('th', { text: 'kind' }), h('th', { text: 'target' }), h('th', { text: 'tools' })));
        o.upstreams.forEach(function (u) { up.appendChild(h('tr', null, h('td', { text: u.name }), h('td', { text: u.kind }), h('td', { text: u.target }), h('td', { text: u.tools ? u.tools.join(', ') : 'offered by the server; use Check and connect' }))); });
        var errs = o.findings.filter(function (f) { return f.level === 'error'; }).length;
        var warns = o.findings.filter(function (f) { return f.level === 'warn'; }).length;
        return h('div', null,
          h('h2', { text: 'Overview' }),
          h('div', { class: 'grid' },
            h('div', { class: 'card' }, h('h3', { text: 'Gateway' }), kv([['status', gw], ['key id', o.gatewayKeyid ? short(o.gatewayKeyid) : 'not created yet'], ['mode', o.mode], ['config', o.configFile]])),
            h('div', { class: 'card' }, h('h3', { text: 'Evidence' }), kv([['receipts', String(o.receiptCount)], ['last receipt', o.lastReceiptAt], ['log', o.log.kind === 'remote' ? 'remote ' + o.log.url + (o.log.hashOnly ? ' (hashes only)' : '') : 'local ' + o.log.file], ['precommit', o.precommit.length ? o.precommit.join(', ') : 'none']])),
            h('div', { class: 'card' }, h('h3', { text: 'Who is trusted' }), kv([['principal keys', String(o.principals.length)], ['key ids', o.principals.map(short).join(', ') || 'none'], ['revoked grants', String(o.revokedCount)]])),
            h('div', { class: 'card' }, h('h3', { text: 'Config check' }), h('p', null, h('span', { class: errs ? 'bad' : 'ok', text: errs + ' error' + (errs === 1 ? '' : 's') }), ', ', h('span', { class: warns ? 'warn' : 'muted', text: warns + ' warning' + (warns === 1 ? '' : 's') })), h('button', { class: 'secondary', onclick: function () { show('Check'); } }, 'See the findings'))),
          o.keyProblems.length ? h('div', { class: 'banner bad' }, o.keyProblems.join('. ')) : null,
          h('div', { class: 'card mt' }, h('h3', { text: 'Upstreams' }), up),
          o.facts.length ? h('div', { class: 'card' }, h('h3', { text: 'Fact lookups the gateway makes itself' }), kv(o.facts.map(function (f) { return [f.name, f.tool + ' for ' + f.forTools.join(', ')]; }))) : null);
      });
    },

    Check: function () {
      var out = h('div');
      function run(connect) {
        say(connect ? 'Starting the upstreams to list their tools…' : '');
        clear(out);
        return api('POST', '/api/check', { connect: connect }).then(function (r) { say(''); out.appendChild(h('div', { class: 'card' }, findings(r.findings))); }).catch(fail);
      }
      var box = h('div', null, h('h2', { text: 'Config check' }),
        h('p', { class: 'muted', text: 'What the gateway would fail on at startup, found before it starts. Connecting starts your stdio upstreams and lists the tools every upstream offers.' }),
        h('div', { class: 'row' }, h('button', { class: 'primary', onclick: function () { run(false); } }, 'Run check'), h('button', { class: 'secondary', onclick: function () { run(true); } }, 'Run check and connect to the upstreams')), out);
      run(false);
      return Promise.resolve(box);
    },

    Policy: function () {
      return api('GET', '/api/policy').then(function (p) {
        policyDigest = p.digest;
        var area = h('textarea', { 'aria-label': 'Cedar policy', spellcheck: 'false' });
        area.value = p.text;
        var out = h('div');
        function validate() {
          return api('POST', '/api/policy/validate', { text: area.value }).then(function (r) {
            clear(out);
            if (r.ok) {
              out.appendChild(h('p', { class: 'ok', text: 'The policy parses.' }));
              r.issues.forEach(function (m) { out.appendChild(h('p', { class: 'warn', text: m })); });
            } else r.errors.forEach(function (m) { out.appendChild(h('p', { class: 'bad', text: m })); });
            return r;
          });
        }
        function simulate() {
          return validate().then(function (v) {
            if (!v.ok) return;
            say('Replaying recorded calls against this policy…');
            return api('POST', '/api/policy/simulate', { text: area.value }).then(function (s) {
              say('');
              var r = s.report;
              out.appendChild(h('div', { class: 'card' }, h('h3', { text: 'Replay of recorded calls' }),
                h('p', { class: 'muted', text: 'A replay re-decides calls that already happened. A limit that no recorded call reached, and an argument value that was never sent, are not covered, so a change that widens what is allowed can show no change here.' }),
                h('p', { text: s.replayed + ' verified receipts replayed (' + s.unverified + ' skipped because they did not verify). ' + r.evaluated + ' evaluated, ' + r.unchanged + ' unchanged, ' + r.reconciliations + ' reconciliations (provider reads with no policy decision), ' + r.changeCount + ' would change.' + (r.complete ? '' : ' The replay is incomplete: ' + r.skipped.length + ' calls could not be replayed.') }),
                r.changes.length ? (function () {
                  var t = h('table', null, h('tr', null, h('th', { text: 'receipt' }), h('th', { text: 'tool' }), h('th', { text: 'was' }), h('th', { text: 'would be' })));
                  r.changes.forEach(function (c) { t.appendChild(h('tr', null, h('td', { text: short(c.receiptId) }), h('td', { text: c.tool }), h('td', { text: c.from }), h('td', { class: c.to === 'deny' ? 'bad' : 'warn', text: c.to }))); });
                  return t;
                })() : h('p', { class: 'muted', text: 'No recorded decision would change.' })));
            });
          });
        }
        function save() {
          return validate().then(function (v) {
            if (!v.ok) return;
            var ask = 'Save this policy?\n\nA running gateway applies it from its next call.';
            if (v.issues.length) ask = 'Confirm before saving:\n\n' + v.issues.join('\n\n') + '\n\nSave this policy anyway?';
            if (!window.confirm(ask)) return;
            return api('PUT', '/api/policy', { text: area.value, expectDigest: policyDigest, confirm: v.issues.length > 0 }).then(function (r) {
              policyDigest = r.digest;
              say('Saved (' + short(r.digest) + '). ' + r.note);
            });
          });
        }
        return h('div', null, h('h2', { text: 'Policy' }),
          h('div', { class: 'banner' }, 'A running gateway applies a saved change from its next call; every save is recorded in the audit trail, and the previous version is kept.'),
          h('p', { class: 'muted' }, p.path + ' · ' + short(p.digest)),
          area, h('div', { class: 'row' },
            h('button', { class: 'secondary', onclick: function () { validate().catch(fail); } }, 'Validate'),
            h('button', { class: 'secondary', onclick: function () { simulate().catch(fail); } }, 'Replay recorded calls'),
            h('button', { class: 'primary', onclick: function () { save().catch(fail); } }, 'Save')),
          out,
          p.history.length ? h('div', { class: 'card' }, h('h3', { text: 'Earlier versions kept' }), h('p', { class: 'muted', text: p.history.join(', ') })) : null);
      });
    },

    Grants: function () {
      var area = h('textarea', { 'aria-label': 'Grant', placeholder: 'Paste a grant (the JSON of a grant file)', spellcheck: 'false', class: 'short' });
      var out = h('div');
      var last = null;
      function inspect() {
        return api('POST', '/api/grants/inspect', { grant: area.value }).then(function (g) {
          last = g;
          clear(out);
          out.appendChild(h('div', { class: 'card' }, h('h3', { text: 'Grant' }), kv([
            ['status', h('span', { class: g.status === 'valid' ? 'ok' : 'bad', text: g.status })],
            ['agent', g.agent], ['principal', g.principal], ['scopes', g.scopes.join(', ')], ['issued', g.issuedAt], ['expires', g.expiresAt],
            ['delegated from another grant', g.delegated ? 'yes' : 'no'], ['can delegate', g.canDelegate ? 'yes' : 'no'], ['digest', g.digest], ['why not valid', g.error]]),
            h('div', { class: 'row' }, g.revoked ? h('span', { class: 'pill', text: 'already revoked' }) : h('button', { class: 'danger', onclick: function () { revoke().catch(fail); } }, 'Revoke this grant'))));
        });
      }
      function revoke() {
        if (!last || !window.confirm('Revoke the grant for ' + last.agent + '?\n\nIt, and every grant delegated from it, is refused on its next call. This cannot be undone here.')) return Promise.resolve();
        return api('POST', '/api/grants/revoke', { grant: area.value }).then(function (r) { say('Revoked the grant for ' + r.agent + '. ' + r.note); return inspect().then(list); });
      }
      var revoked = h('div');
      function list() {
        return api('GET', '/api/revocations').then(function (r) {
          clear(revoked);
          revoked.appendChild(h('div', { class: 'card' }, h('h3', { text: 'Revoked grants (' + r.digests.length + ')' }), r.digests.length ? h('table', null, r.digests.map(function (d) { return h('tr', null, h('td', null, h('code', { text: d }))); })) : h('p', { class: 'muted', text: 'None.' })));
        });
      }
      list().catch(fail);
      return Promise.resolve(h('div', null, h('h2', { text: 'Grants' }),
        h('p', { class: 'muted', text: 'The gateway does not store grants: each agent presents its own. Paste one to see whether the gateway would accept it, and to revoke it. The console never holds a principal key and cannot issue a grant.' }),
        area, h('div', { class: 'row' }, h('button', { class: 'primary', onclick: function () { inspect().catch(fail); } }, 'Inspect')), out, revoked));
    },

    Receipts: function () {
      return api('GET', '/api/receipts?limit=100').then(function (r) {
        var detail = h('div');
        var filter = h('select', { 'aria-label': 'Filter by status' }, h('option', { value: '' }, 'all'), h('option', { value: 'executed' }, 'executed'), h('option', { value: 'denied' }, 'denied'), h('option', { value: 'withheld' }, 'withheld'), h('option', { value: 'failed' }, 'failed'));
        var body = h('table');
        function draw() {
          clear(body);
          body.appendChild(h('tr', null, h('th', { text: 'time' }), h('th', { text: 'agent' }), h('th', { text: 'tool' }), h('th', { text: 'decision' }), h('th', { text: 'outcome' }), h('th', { text: 'verifies' })));
          r.receipts.filter(function (x) { return !filter.value || x.status === filter.value; }).forEach(function (x) {
            body.appendChild(h('tr', { class: 'click', onclick: function () { open(x.id); } },
              h('td', { text: x.timestamp || '-' }), h('td', { text: x.agent || '-' }), h('td', { text: x.tool || '-' }),
              h('td', { class: x.decision === 'deny' ? 'bad' : '', text: x.decision ? x.decision + (x.enforced ? '' : ' (not enforced)') : '-' }),
              h('td', { text: x.status ? x.status + (x.reason ? ': ' + x.reason : '') : '-' }),
              h('td', { class: x.verified ? 'ok' : 'bad', text: x.verified ? 'yes' : 'NO: ' + (x.failing || []).join(', ') })));
          });
        }
        function open(id) {
          api('GET', '/api/receipts/' + encodeURIComponent(id)).then(function (d) {
            clear(detail);
            detail.appendChild(h('div', { class: 'card' }, h('h3', { text: 'Receipt ' + id }), h('pre', { text: JSON.stringify(d.statement, null, 2) })));
            detail.scrollIntoView();
          }).catch(fail);
        }
        filter.addEventListener('change', draw);
        draw();
        return h('div', null, h('h2', { text: 'Receipts' }),
          h('p', { class: 'muted', text: r.total + ' receipts on disk, the newest ' + r.receipts.length + ' shown. Each is verified against the gateway key, the trusted principals, and the local log.' }),
          r.problems.length ? h('div', { class: 'banner bad' }, r.problems.join('. ')) : null,
          h('div', { class: 'row' }, h('label', null, 'Outcome ', filter)), h('div', { class: 'card' }, body), detail);
      });
    },

    Audit: function () {
      return api('GET', '/api/audit').then(function (a) {
        var t = h('table', null, h('tr', null, h('th', { text: 'when' }), h('th', { text: 'by' }), h('th', { text: 'action' }), h('th', { text: 'detail' })));
        a.entries.forEach(function (e) {
          var rest = {}; Object.keys(e).forEach(function (k) { if (k !== 'at' && k !== 'by' && k !== 'action') rest[k] = e[k]; });
          t.appendChild(h('tr', null, h('td', { text: e.at }), h('td', { text: e.by }), h('td', { text: e.action }), h('td', null, h('code', { text: JSON.stringify(rest) }))));
        });
        return h('div', null, h('h2', { text: 'Audit trail' }), h('p', { class: 'muted', text: 'Every change made here: who, when, and what.' }), h('div', { class: 'card' }, a.entries.length ? t : h('p', { class: 'muted', text: 'No changes yet.' })));
      });
    }
  };

  function show(name) {
    current = name;
    say('');
    Array.prototype.forEach.call(document.querySelectorAll('nav button'), function (b) { if (b.textContent === name) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    clear(view).appendChild(h('p', { class: 'muted', text: 'Loading…' }));
    renderers[name]().then(function (el) { clear(view).appendChild(el); }).catch(function (e) { clear(view); fail(e); });
  }

  var nav = document.getElementById('nav');
  tabs.forEach(function (n) { nav.appendChild(h('button', { type: 'button', onclick: function () { show(n); } }, n)); });
  document.getElementById('signout').addEventListener('click', signOut);
  document.getElementById('theme').addEventListener('click', function () {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark' || (!document.documentElement.getAttribute('data-theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
    var next = dark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem(THEME, next); } catch (e) {}
  });
  document.getElementById('login-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    token = document.getElementById('token').value.trim();
    document.getElementById('token').value = '';
    api('GET', '/api/audit').then(function () {
      try { sessionStorage.setItem(KEY, token); } catch (e) {}
      document.getElementById('login').hidden = true;
      document.getElementById('app').hidden = false;
      show(current);
    }).catch(function (e) { clear(document.getElementById('login-msg')).appendChild(h('p', { class: 'bad', role: 'alert', text: e.message })); });
  });
  if (token) {
    api('GET', '/api/audit').then(function () { document.getElementById('login').hidden = true; document.getElementById('app').hidden = false; show(current); }).catch(function () { signOut(); });
  }
})();
`;

const sha = (s: string) => `'sha256-${createHash("sha256").update(s).digest("base64")}'`;

export const CONSOLE_CSP = `default-src 'none'; style-src ${sha(STYLE)}; script-src ${sha(SCRIPT)}; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;

export const CONSOLE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-custody console</title>
<style>${STYLE}</style>
</head>
<body>
<section id="login" class="card">
  <h2>agent-custody console</h2>
  <p class="muted">Sign in with the console's token. It is kept for this browser tab only.</p>
  <form id="login-form"><div class="row"><label for="token">Token</label><input id="token" type="password" autocomplete="off" required><button class="primary" type="submit">Sign in</button></div></form>
  <div id="login-msg"></div>
</section>
<div id="app" hidden>
  <header><h1>agent-custody console</h1><nav id="nav" aria-label="Sections"></nav><button id="theme" type="button" class="secondary">Theme</button><button id="signout" type="button" class="secondary">Sign out</button></header>
  <main><div id="msg"></div><div id="view"></div></main>
</div>
<script>${SCRIPT}</script>
</body>
</html>
`;

export { SCRIPT as CONSOLE_SCRIPT };
