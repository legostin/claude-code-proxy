# proxy: an HTTPS debugging proxy inside Claude Code

[![CI](https://github.com/legostin/claude-code-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/legostin/claude-code-proxy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Claude Code mod](https://img.shields.io/badge/Claude%20Code-mod-d97757.svg)](https://claude.com/claude-code)

**proxy** is a [Claude Code](https://claude.com/claude-code) mod (a plugin of function hooks).
It turns Claude Code into an HTTPS debugging proxy in the spirit of Proxyman, Charles or mitmproxy:
it intercepts and decrypts the HTTP and HTTPS traffic of your browser, the iOS Simulator, an iPhone,
the Android emulator or an Android phone. It shows every request in a filterable list, and lets
Claude read the same traffic, so you can ask *"why does the login request return 401?"* and it
looks at the real request and response.

[Website](https://legostin.github.io/claude-code-proxy/) · [Install](#install) · [Design notes](docs/design.md)

```
● 127.0.0.1:8899 · 342 requests              [ Stop ] [ Tree ] [ Clear ] [ Setup ]
Filter host:*.api.example.com is:error
401  POST    https://api.example.com/v1/login                     1.2KB   180ms
503  GET     https://api.example.com/v1/feed                        87B    2.1s
CERT CONNECT gateway.icloud.com:443                                   0B     0ms
```

## Why

Debugging a mobile or web client usually means a separate proxy app, a certificate dance on every
device, and copying requests into the chat by hand. **proxy** keeps all of it where you already
work:

- **No separate app.** The proxy, its certificate authority and the request list live in Claude Code.
- **One click for a browser.** It opens a separate Chrome, Edge, Brave or Chromium window whose
  whole traffic goes through the proxy, localhost included, with **no certificate to install**.
- **Simulators and emulators set up for you.** The CA goes into every booted iOS Simulator with one
  button. The Android emulator, or a phone on USB, is pointed at the proxy with another, and pointed
  back when you stop.
- **Claude sees the traffic.** Two tools give the model the request list and any request in full:
  headers and decoded bodies.

## Features

- MITM HTTPS proxy: decrypts TLS with per-host certificates from its own local CA. Plain HTTP,
  WebSocket upgrades and server-sent events pass through.
- Request list with a filter language: `method:POST status:4xx host:*.example.com type:json is:error -text`.
- A tree view: requests grouped by host and path, each node with its request and failure counts.
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
- No dependencies: a Node.js sidecar and `openssl`, nothing to install from npm.

## Install

Requires Claude Code with mods (tested on 2.1.292), Node.js 18 or newer, and `openssl` (built into
macOS). At the Claude Code prompt:

```
/plugin install proxy --marketplace legostin/claude-code-proxy
```

Answer `y` to add the marketplace and pick a scope. Then:

```
/proxy            open the pane and start the proxy
/proxy setup      set up a browser, iOS, Android, macOS or CLI client
/proxy stop       stop it (and point Android devices back)
/proxy clear      clear the list
/proxy status     one line about its state
```

## Set up a client

| Client | How |
| --- | --- |
| A separate browser | **Setup → Browser → Open Google Chrome** (or Edge, Brave, Chromium). It starts a new instance with a profile of its own, `--proxy-server`, `--proxy-bypass-list=<-loopback>` so localhost is captured too, and `--ignore-certificate-errors-spki-list` so it trusts the proxy's certificates without touching the keychain. |
| iOS Simulator | **Setup → iOS → CA → simulators** runs `xcrun simctl keychain add-root-cert` on every booted simulator. The simulator uses the macOS system proxy; the tab copies the `networksetup` commands to turn it on and off. |
| iPhone / iPad | **Setup → iOS → Listen on LAN**, scan the QR code with the Camera to install the profile, turn it on under **Certificate Trust Settings**, then set the Wi-Fi proxy to the server and port the tab shows. |
| Android emulator / phone on USB | **Setup → Android → Android → proxy** points an emulator at `10.0.2.2:8899`, and a USB device at `127.0.0.1:8899` over `adb reverse`. **Revert**, stopping the proxy or ending the session points them back. |
| Android phone on Wi-Fi | **Setup → Android → Listen on LAN**, scan the QR code to download the certificate and install it, then set the Wi-Fi proxy to the hostname and port the tab shows. Apps trust user CAs only with a `network_security_config`; **config snippet** copies one. |
| curl, Node, Python, Go | `curl -x http://127.0.0.1:8899 --cacert ~/.claude/proxy-mod/ca/ca.pem …`; **Setup → macOS / CLI** copies `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`. |

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
| `mcp__proxy__list_requests({ filter?, limit? })` | The proxy's state and one line per request: id, method, status, URL, size, time, type, error. |
| `mcp__proxy__get_request({ id, max_body_chars? })` | One request in full: URL, status, timing, client, error, request and response headers, decoded bodies. |

Ask things like *"list the failed requests to api.example.com and tell me what they have in
common"* or *"compare request #12 with #14"*. **To prompt** in a request's detail starts such a
question for you.

## Options

Set them in `/config` or with `/plugin configure proxy@proxy`.

| Option | Default | |
| --- | --- | --- |
| Port | `8899` | |
| Listen on | `local` | `lan` opens the proxy to phones on the network |
| Hosts not to decrypt | `*.apple.com,*.icloud.com,*.mzstatic.com,*.apple-cloudkit.com` | tunnelled untouched |
| Requests kept | `2000` | |
| Node executable | `node` | |

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

## FAQ

**Is it a replacement for Proxyman, Charles or mitmproxy?**
For everyday "what did my app send and what came back" debugging, yes, without leaving Claude Code.
It has no breakpoints, rewrite rules, HTTP/2 or gRPC.

**Do I have to install the certificate on my Mac?**
Not for the separate browser: it trusts the proxy by SPKI hash. Safari, native macOS apps and the
iOS Simulator need the CA trusted; the setup tabs give the commands.

**Why do some requests show `CERT`?**
The client refused the proxy's certificate. Either its CA is not trusted yet (finish the setup
steps), or the app pins its certificates; add such hosts to *Hosts not to decrypt*.

**Does my traffic leave my machine?**
No. The proxy listens on `127.0.0.1` unless you choose `lan`, and recorded requests stay in
`~/.claude/proxy-mod`. Claude reads a request only when it calls the tools.

**Does it capture Claude Code's own traffic, or the commands Claude runs?**
No. It captures clients you point at it.

## Limits

- Clients are offered HTTP/1.1 only, so gRPC over HTTP/2 does not get through.
- WebSocket frames are not decoded; an upgrade shows as one row.
- The macOS system proxy is not switched automatically: if the session died with it on, the Mac
  would lose its network until it is turned off.
- Mods are an early-access Claude Code API.

## Development

```sh
node --test sidecar/proxy.spec.mjs    # the proxy, against local upstreams, driven by curl
claude plugin test .                  # the logic, the pane (terminal and desktop) and the tools
claude plugin validate .
```

To run a working copy: `claude --plugin-dir /path/to/claude-code-proxy`.

## License

[MIT](LICENSE). Not affiliated with Anthropic, Proxyman, Charles or mitmproxy.
