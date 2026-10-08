# Wirepane: an HTTPS debugging proxy inside Claude Code

[![CI](https://github.com/legostin/wirepane/actions/workflows/ci.yml/badge.svg)](https://github.com/legostin/wirepane/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Claude Code mod](https://img.shields.io/badge/Claude%20Code-mod-d97757.svg)](https://claude.com/claude-code)

**Wirepane** is a [Claude Code](https://claude.com/claude-code) mod (a plugin of function hooks).
It turns Claude Code into an HTTPS debugging proxy in the spirit of Proxyman, Charles or mitmproxy:
it intercepts and decrypts the HTTP and HTTPS traffic of your browser, the iOS Simulator, an iPhone,
the Android emulator or an Android phone. It shows every request in a filterable list, and lets
Claude read the same traffic, so you can ask *"why does the login request return 401?"* and it
looks at the real request and response.

[Website](https://legostin.github.io/wirepane/) · [Install](#install) · [What it runs and changes](#what-it-runs-and-what-it-changes) · [Design notes](docs/design.md)

## Install

Requires macOS, Claude Code 2.1.292 or newer, and `openssl` (built into macOS). The proxy runs on
Node.js 18 or newer, which it finds by itself: on PATH, or where Homebrew, Volta, nvm, fnm, mise,
asdf, nodenv or MacPorts put it. With none, the pane offers to install it. At the Claude Code prompt:

```
/plugin install wirepane --marketplace legostin/wirepane
```

Answer `y` to add the marketplace and pick a scope. The same from a shell:

```sh
claude plugin marketplace add legostin/wirepane
claude plugin install wirepane@wirepane
```

Then run `/proxy`: the proxy starts on `127.0.0.1:8899` and the pane opens. An empty list offers
the ways in it found on this Mac.

```
● 127.0.0.1:8899 · 342 requests              [ Stop ]  View [ List ] [ Tree ]  [ Clear ] [ Setup ]
Filter host:*.api.example.com is:error
401  POST    https://api.example.com/v1/login                     1.2KB   180ms
503  GET     https://api.example.com/v1/feed                        87B    2.1s
CERT CONNECT gateway.icloud.com:443                                   0B     0ms
```

The command takes:

```
/proxy            open the pane and start the proxy
/proxy setup      set up a browser, iOS, Android, macOS or CLI client
/proxy stop       stop it (and point Android devices back)
/proxy clear      clear the list
/proxy rules      the rules that change requests and responses
/proxy track      the domains this session decrypts and records
/proxy status     one line about its state
/proxy tree       show the requests as a tree (host → path → requests)
/proxy list       show them as a flat list
```

## Why

Debugging a mobile or web client usually means a separate proxy app, a certificate dance on every
device, and copying requests into the chat by hand. **Wirepane** keeps all of it where you already
work:

- **No separate app.** The proxy, its certificate authority and the request list live in Claude Code.
- **A quick start where you land.** An empty list offers the ways in found on this Mac: open a
  browser, use a simulator, start an emulator, set up a phone, track only your app.
- **One click for a browser.** It opens a separate Chrome, Edge, Brave or Chromium window whose
  whole traffic goes through the proxy, localhost included, with **no certificate to install**.
- **Simulators and emulators set up for you.** Pick a simulator from the list and press **Use**: it
  boots, gets the CA, and the Mac's system proxy points at the proxy. Pick an Android emulator and
  it starts with its traffic already going through the proxy.
- **Claude Code keeps working.** With the macOS system proxy on, every app on the Mac goes through
  the proxy; Claude's hosts bypass it and anything Claude runs is tunnelled, never decrypted.
- **Claude sees the traffic.** Two tools give the model the request list and any request in full:
  headers and decoded bodies.

## Features

- MITM HTTPS proxy: decrypts TLS with per-host certificates from its own local CA. Plain HTTP,
  WebSocket upgrades and server-sent events pass through.
- Request list with a filter language: `method:POST status:4xx host:*.example.com type:json is:error -text`.
- A tree view: requests grouped by host and path, each node with its request and failure counts.
  Switch with **View: List / Tree** in the pane (`l` / `t`) or `/proxy tree`; the choice is remembered.
- The exact proxy address for each client: the Mac's Wi-Fi address for a phone, picked over VPN tunnels and
  virtual machine bridges, and a QR code the phone scans to open the setup page and get the certificate.
- Request detail: headers, pretty-printed JSON, gzip, brotli, deflate and zstd decoded,
  **Copy as curl**, **To prompt**.
- Diagnoses certificate trouble: a client that refuses the proxy certificate (CA not trusted, or
  certificate pinning) shows up as a `CERT` row instead of silently failing.
- Setup page served by the proxy itself at `http://claude.proxy/`: an iOS `.mobileconfig`, an
  Android `.crt` and a `.pem`.
- Hosts to tunnel without decryption (pinned services), Apple's by default.
- Safe on the network: in `lan` mode, phones can use the proxy, but nothing on the network can use
  it to reach this Mac's localhost.
- Tracked domains per session: decrypt and record only your app's hosts (wildcards welcome);
  everything else passes through untouched, so a phone's own services keep working.
- A rules engine: delays, throttling, mocks, rewritten headers, URLs and bodies, status codes,
  dropped connections and scripts, chained by priority; managed in the pane and by Claude.
- No dependencies: a Node.js sidecar and `openssl`, nothing to install from npm.

## Set up a client

| Client | How |
| --- | --- |
| A separate browser | **Setup → Browser → Open Google Chrome** (or Edge, Brave, Chromium). It starts a new instance with a profile of its own, `--proxy-server`, `--proxy-bypass-list=<-loopback>` so localhost is captured too, and `--ignore-certificate-errors-spki-list` so it trusts the proxy's certificates without touching the keychain. |
| iOS Simulator | **Setup → iOS**: the simulators on this Mac, booted first. **Use** (or **Boot & use**) boots one, adds the CA (`simctl keychain add-root-cert`) and turns the macOS system proxy on, since a simulator has no proxy setting of its own. |
| iPhone / iPad | **Setup → iOS → iPhone / iPad**: **Listen on LAN**, scan the QR code with the Camera to install the profile, turn it on under **Certificate Trust Settings**, then set the Wi-Fi proxy to the server and port shown. The section confirms when the phone's traffic arrives, and says so when the phone refuses the certificate. |
| Android emulator | **Setup → Android → Emulator**: your AVDs. **Start through the proxy** launches one with `-http-proxy`, waits for it to boot and opens the CA page in its browser: one tap installs the certificate. A running emulator is pointed at the proxy with **Android → proxy** (`10.0.2.2`) and back with **Revert**. |
| Android phone on USB | **Setup → Android → Phone**: **Point USB phones at the proxy** uses `adb reverse`, so no Wi-Fi is needed. |
| Android phone on Wi-Fi | **Setup → Android → Phone**: **Listen on LAN**, scan the QR code to download the certificate and install it, then set the Wi-Fi proxy to the hostname and port shown. Apps trust user CAs only with a `network_security_config`; **config snippet** copies one. |
| Safari and native Mac apps | **Setup → macOS → Turn on for this Mac** points the system proxy here (Claude's hosts on its bypass list), **Trust CA on this Mac** adds the CA to the login keychain. Both are put back when the proxy stops. |
| curl, Node, Python, Go | `curl -x http://127.0.0.1:8899 --cacert ~/.claude/proxy-mod/ca/ca.pem …`; **Setup → macOS / CLI** copies `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`. |

## Claude Code keeps working

Claude Code does not trust the proxy's CA, so a connection of its own that the proxy decrypted
would fail; with the macOS system proxy on, its traffic would come here like every app's. Two
guards keep it whole:

- Anthropic's and Claude's hosts (`*.anthropic.com`, `*.claude.ai`, `*.claude.com`) are on the
  system proxy's bypass list, and the proxy never decrypts them anyway.
- While the system proxy points at the proxy, a local connection whose process descends from
  Claude (any Claude Code session, the commands and MCP servers it runs, the Claude app) is
  tunnelled untouched. Every other app is decrypted as usual.

The system proxy switch keeps the settings it replaced and puts them back when the proxy stops,
when the session ends, and, from the proxy itself, if Claude Code quits.

## Tracked domains

A phone talks to dozens of hosts: push, iCloud, analytics, other apps. Turn on the tracking list
and the proxy decrypts and records only the domains you name; every other connection passes
through untouched and unrecorded, so the phone's own services keep working (no `CERT` failures on
pinned hosts) and the list holds your app's traffic alone.

```
/proxy track app.kolesa.kz *.kolesa.kz     track these (wildcards: *.example.com covers example.com)
/proxy untrack app.kolesa.kz               stop tracking one
/proxy untrack                             switch the list off: every domain again
/proxy track                               open the Domains view
```

The **Domains** view (`d`) lists the patterns with how many requests each caught, switches the
list on and off, and shows the hosts that passed through untracked, busiest first, each with
**track** and **track \*.domain** buttons: connect the phone, use the app, and pick its hosts from
there. The list belongs to the Claude Code session and comes back with `--resume`. Claude manages
it with `mcp__wirepane__track_domains`.

## Rules: change requests and responses

Rules change matching requests before they are sent and their responses before the client gets
them: slow an endpoint down, answer it with a mock, flip a status code, rewrite a JSON field, send
`/v1/*` to your local server, drop the connection. Ask Claude in plain words ("make GET /api/feed
take 3 seconds", "answer POST /login with a 500") and it writes the rule; the **Rules** view
(`/proxy rules`, or `r` in the pane) lists them with what each does in words, turns them on and
off, and moves them up and down.

Rules live in the project, in `.claude/proxy-rules.json`, so they can be committed and shared. The
proxy reloads the file the moment it changes.

```json
{
  "rules": [
    {
      "id": "slow-feed",
      "description": "Simulate a slow backend for the feed",
      "match": { "methods": ["GET"], "host": "api.example.com", "path": "/v1/feed*" },
      "request": [{ "type": "delay", "ms": 2000 }],
      "response": [
        { "type": "setStatus", "status": 503 },
        { "type": "mergeJson", "json": { "error": "down" } }
      ]
    }
  ]
}
```

**Order and chaining.** The first rule applies first. Every matching rule that is on applies, in
order, and the actions inside a rule apply in order; `"stop": true` ends the chain.

**Match.** Every condition given must hold: `url`, `host`, `path` (globs such as `*.example.com` or
`/v1/*`, or `re:<regex>`), `methods`, `headers`, `query`, `bodyContains`, and on the response side
`status` (`404`, `4xx`, `>=400`, `500-599`) and `contentType`.

| Action | Before sending | On the response |
| --- | :-: | :-: |
| `delay {ms, msMax?}`, `throttle {bytesPerSecond}` | ✓ | ✓ |
| `setHeader {name, value}`, `removeHeader {name}` | ✓ | ✓ |
| `setQuery`, `removeQuery` | ✓ | |
| `mapRemote {scheme?, host?, port?, path?}`, `replaceUrl {pattern, with}` | ✓ | |
| `setBody {text \| json \| file}`, `replaceBody {pattern, with}`, `mergeJson {json}` | ✓ | ✓ |
| `respond {status, headers?, text \| json \| file}`: answer without the server | ✓ | |
| `setStatus {status}` | | ✓ |
| `fail {kind: reset \| close \| timeout}` | ✓ | ✓ |
| `script {code}` | ✓ | ✓ |

A response body is held back only when a rule changes it (decoded from gzip or brotli first);
rules that change only headers or the status keep the response streaming, so server-sent events
still work.

**Scripts.** `code` is the body of `async (req, res, ctx) => {}`, run in the proxy: before sending
it can change `req.method`, `req.url`, `req.headers`, `req.body` or set
`req.respond = { status, headers, body }`; on the response it can change `res.status`,
`res.headers` and `res.body` (`req.json()` and `res.json()` parse the bodies). A script runs only
once its SHA-256 is approved, so a rules file that came with a cloned repository cannot run code on
your machine unasked: press **Allow script** in the Rules view. Scripts Claude adds through its tools
are approved with them.

**In the list,** a request a rule changed is marked `✎`; its detail says what each rule did, and
the filter takes `is:modified` and `rule:<id>`.

## Filter

Terms separated by spaces must all hold, and a leading `-` negates a term. Free text matches a
substring of the URL.

| Term | Matches |
| --- | --- |
| `method:POST`, `method:get,post` | the method |
| `status:404`, `status:4xx`, `status:>=400`, `status:500-599` | the response status |
| `host:api.example.com`, `host:*.example.com` | the host (a substring, or a glob) |
| `path:/v1/login` | a substring of the path |
| `type:json\|html\|xml\|js\|css\|img\|font\|media\|text\|form\|ws\|tunnel\|other` | the content type |
| `is:error\|ok\|pending\|tunnel\|ws\|https\|rejected` | the state (`rejected`: the client refused the certificate) |
| `client:192.168.1.20` | the client's address |

For example, `host:*.api.com -type:img is:error`.

## Tools for Claude

| Tool | What the model gets |
| --- | --- |
| `mcp__wirepane__list_requests({ filter?, limit? })` | The proxy's state and one line per request: id, method, status, URL, size, time, type, error. |
| `mcp__wirepane__get_request({ id, max_body_chars? })` | One request in full: URL, status, timing, client, error, request and response headers, decoded bodies, what the rules did. |
| `mcp__wirepane__track_domains({ add?, remove?, set?, enabled? })` | The session's tracked domains, and the untracked hosts the proxy has seen, busiest first. |
| `mcp__wirepane__list_rules()` | The rules in order, on or off, what each does in words, errors, how many requests each changed. |
| `mcp__wirepane__add_rule({ rule, position? })`, `update_rule({ id, changes?, enabled?, position? })`, `remove_rule({ id })` | Write the rules file; the proxy applies the change at once. |

Ask things like *"list the failed requests to api.example.com and tell me what they have in
common"* or *"compare request #12 with #14"*. **To prompt** in a request's detail starts such a
question for you.

## Options

Set them in `/config`, or in `/plugin` → **Installed** → **wirepane** → **Configure options**.

| Option | Default | |
| --- | --- | --- |
| Port | `8899` | |
| Listen on | `local` | `lan` opens the proxy to phones on the network |
| Hosts not to decrypt | `*.apple.com,*.icloud.com,*.mzstatic.com,*.apple-cloudkit.com` | tunnelled untouched |
| Requests kept | `2000` | |

## How it works

```
Claude Code mod ──spawns──▶ node sidecar/proxy.mjs ◀── :8899 ── browser · simulator · phone
      ▲                          │ JSON lines: one summary per request
      │                          │ headers and bodies → ~/.claude/proxy-mod/flows/
   pane · status line · tools    │ openssl → ~/.claude/proxy-mod/ca, certs
```

A mod runs sandboxed, with no sockets of its own, so the proxy is a small Node.js process the mod
starts for the session. It terminates TLS with a certificate per host, signed by a CA made on your
machine (RSA-2048, kept in `~/.claude/proxy-mod/ca`, the key readable by you only). Request
summaries come back on stdout; headers and bodies stay on disk and are read only when you open a
request or Claude asks for one. [docs/design.md](docs/design.md) has the details.

## What it runs and what it changes

Wirepane sends nothing of its own anywhere: no telemetry, no update checks, no downloads. The only
connections it makes are the ones it relays for the clients you point at it, to the servers those
clients asked for. A request reaches Claude only when Claude calls one of the
[tools](#tools-for-claude); what it reads then becomes part of the conversation, like a file Claude
reads.

While the proxy is on, it runs:

- `node sidecar/proxy.mjs`, the proxy itself, on `127.0.0.1` (on the network too in `lan` mode),
  stopped with `kill` when you stop the proxy or the session ends. It runs on the first Node from
  the places under [Install](#install) that answers `--version` with 18 or newer.
- `openssl`, to make the CA and a certificate for each host.
- `route`, `networksetup` and `scutil`, to find this Mac's addresses and read the system proxy, and
  `ps` and `lsof`, to tell Claude's own connections apart so that they are tunnelled, never decrypted.

Only when you press the button for it:

| In the pane | Runs | Changes |
| --- | --- | --- |
| **macOS → Turn on for this Mac**, **iOS → Use** | `networksetup`, through `osascript` when macOS asks for an administrator | The system proxy, put back when the proxy stops |
| **macOS → Trust CA on this Mac** | `security add-trusted-cert`, which macOS asks you to confirm | The CA in your login keychain |
| **iOS → Use**, **Boot & use** | `xcrun simctl`, `open -a Simulator` | The CA in that simulator's keychain |
| **Browser → Open** | `open -na <browser>` with a profile of its own | Nothing outside `~/.claude/proxy-mod/browser` |
| **Android → Start through the proxy** | `emulator -avd <name> -http-proxy …`, `adb` | Nothing: the proxy setting lasts for that run |
| **Install Node.js**, shown when no Node was found | `brew install node`, then the proxy starts | Node.js from Homebrew |
| **Download Node.js**, the same without Homebrew | `open https://nodejs.org/en/download` | Nothing |
| **Android → proxy**, **Point USB phones at the proxy** | `adb shell settings put global http_proxy`, `adb reverse` | The device's proxy, put back by **Revert** and when the proxy stops |

Files it writes:

- `~/.claude/proxy-mod/ca` and `certs`: the CA (RSA-2048, the key readable by you only) and the
  certificates made from it.
- `~/.claude/proxy-mod/flows/<session>`: the headers and bodies of recorded requests. They can hold
  the passwords, tokens and personal data of the apps you debug. A session's folder is deleted two
  days after its last use.
- `~/.claude/proxy-mod/sessions`, `trusted-scripts.json` and `system-proxy-backup.json`: each
  session's tracked domains, the rule scripts you approved, and the system proxy settings to put
  back.
- `<project>/.claude/proxy-rules.json`, once you or Claude add a rule.

## Uninstall

1. `/proxy stop` puts back the system proxy and the Android devices it pointed here.
2. `/plugin uninstall wirepane@wirepane`, or **Uninstall** in `/plugin` → **Installed**.
3. Remove the CA where you trusted it: in Keychain Access on the Mac (search for *Wirepane CA*),
   under **Settings → General → VPN & Device Management** on an iPhone, and under user
   credentials on Android.
4. `rm -rf ~/.claude/proxy-mod` deletes the CA, the recorded requests and the browser profiles.

## FAQ

**Is it a replacement for Proxyman, Charles or mitmproxy?**
For everyday "what did my app send and what came back" debugging, yes, without leaving Claude Code.
Rules cover rewriting, mocking and throttling; there are no interactive breakpoints, HTTP/2 or gRPC.

**Do I have to install the certificate on my Mac?**
Not for the separate browser: it trusts the proxy by SPKI hash. Safari, native macOS apps and the
iOS Simulator need the CA trusted; the setup tabs give the commands.

**Why do some requests show `CERT`?**
The client refused the proxy's certificate. Either its CA is not trusted yet (finish the setup
steps), or the app pins its certificates; add such hosts to *Hosts not to decrypt*.

**Does my traffic leave my machine?**
Only for the servers it was going to anyway. The proxy listens on `127.0.0.1` unless you choose
`lan`, and recorded requests stay in `~/.claude/proxy-mod`. Claude reads a request only when it
calls the tools, and then that request is part of the conversation.

**Does it capture Claude Code's own traffic, or the commands Claude runs?**
No. It captures clients you point at it.

## Limits

- Clients are offered HTTP/1.1 only, so gRPC over HTTP/2 does not get through.
- WebSocket frames are not decoded; an upgrade shows as one row.
- The system proxy is put back on stop, at the session's end and when Claude Code quits; only a
  proxy killed with `kill -9` can leave it on (System Settings → Network → Details → Proxies).
- Rule scripts run in Node's `vm` module inside the proxy: approve only code you would run yourself.
- Mods are an early-access Claude Code API.

## Development

```sh
node --test sidecar/proxy.spec.mjs    # the proxy, against local upstreams, driven by curl
claude plugin test .                  # the logic, the pane (terminal and desktop) and the tools
claude plugin validate --strict .
```

To run a working copy: `claude --plugin-dir /path/to/wirepane`.

## License

[MIT](LICENSE). Not affiliated with Anthropic, Proxyman, Charles or mitmproxy.
