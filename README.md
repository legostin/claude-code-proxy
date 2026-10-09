# Wirepane: the debugging proxy that Claude can read

[![CI](https://github.com/legostin/wirepane/actions/workflows/ci.yml/badge.svg)](https://github.com/legostin/wirepane/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Claude Code mod](https://img.shields.io/badge/Claude%20Code-mod-d97757.svg)](https://claude.com/claude-code)

**Wirepane** turns [Claude Code](https://claude.com/claude-code) into an HTTPS debugging proxy for the browser, the iOS Simulator, iPhones, the Android emulator and Android phones. It is a mod: a plugin of function hooks. It decrypts HTTP/1.1, HTTP/2, gRPC, WebSockets and server-sent events, shows them in a pane next to your conversation, and gives Claude the same traffic through 16 tools.

So instead of copying requests into the chat, you ask:

> *"Why does checkout return 402 on the phone but not in the browser?"*
> *"Wait while I tap Log in, then tell me what the app sent."*
> *"Make the feed take 3 seconds and fail one request in five."*
> *"Answer the price socket with a mock that sends a tick every subscription."*
> *"Nothing shows up from the emulator. Fix it."*

Claude finds the request, reads only the part it needs, compares the one that works with the one that fails, replays it with a change, writes a rule, and fixes your code. When something is in the way, a missing CA, a pinned certificate, a VPN or Charles holding the system proxy, the doctor names it and fixes it.

[Website](https://legostin.github.io/wirepane/) · [Install](#install) · [What Claude can do](#tools-for-claude) · [Doctor](#the-doctor) · [Rules](#rules) · [Limits](#limits) · [Design notes](docs/design.md)

## Install

You need macOS, Claude Code 2.1.292 or newer, and `openssl` (built into macOS).

The proxy runs on Node.js 18 or newer and finds it by itself: on PATH, or where Homebrew, Volta, nvm, fnm, mise, asdf, nodenv or MacPorts put it. With no Node at all, the pane offers to install it.

At the Claude Code prompt:

```
/plugin install wirepane --marketplace legostin/wirepane
```

Or from a shell:

```sh
claude plugin marketplace add legostin/wirepane
claude plugin install wirepane@wirepane
```

Then run `/proxy`. The proxy starts on `127.0.0.1:8899`, the pane opens, and an empty list offers the ways in it found on this Mac: a browser, a booted simulator, an emulator, a phone.

```
● 127.0.0.1:8899 · 342 requests          [ Stop ]  View [ List ] [ Tree ]  [ Clear ] [ Setup ] [ Rules (2) ] [ Health (1) ]
Filter host:*.api.example.com is:error
401  POST    https://api.example.com/v1/login                     1.2KB   180ms
200  POST    ✎ https://api.example.com/pkg.Cart/Checkout             41B    95ms
101  GET     wss://api.example.com/chat                          ↑14 ↓52       …
CERT CONNECT gateway.icloud.com:443                                   0B     0ms
```

## What is in it

**It reads every protocol a modern app speaks.**
- **HTTP/2** to clients that offer it, and to servers that speak it. HTTP/1.1 for the rest, both ways independently. Plain-text HTTP/2 (h2c, prior knowledge) too, as a gRPC client speaks it to a local service through the proxy.
- **gRPC and gRPC-Web**, with trailers forwarded. Bodies are decoded without a schema: field numbers, values, nested messages. A failed call shows its status, `gRPC NOT_FOUND: no such user`.
- **Protobuf** bodies (`application/x-protobuf`), decoded the same way.
- **WebSockets**, message by message, both ways, with timing and close codes. Compression is taken out of the offer so every message stays readable. Binary messages are read without a schema: protobuf (bare, after its varint length, or in a gRPC frame), text, and gzip or zlib around them; base64 only when nothing fits. In the detail of a live socket, you can type a message to either side.
- **Server-sent events**, event by event, as they arrive, with the millisecond each one came. Made for LLM streaming APIs.
- gzip, brotli, deflate and zstd, decoded.

**It reaches every client in one press.**
- **A separate browser:** Chrome, Edge, Brave or Chromium, trusting the proxy by SPKI hash. No certificate to install.
- **iOS Simulator:** boots, gets the CA, the system proxy turns on.
- **Android emulator:** starts behind the proxy and opens the CA page. On Google APIs images, *Trust in all apps* makes the CA a system CA.
- **Phones:** the exact address to type and a QR code. `adb reverse` for Android phones on USB, so no Wi-Fi is needed.

**It changes traffic, not just shows it.** A rules engine for requests, responses and WebSocket messages:
- breakpoints: a request or a response held until you or Claude let it go, changed or not;
- mocks, delays, throttling, errors, dropped connections;
- rewritten headers, URLs and JSON;
- sending requests to your local server;
- a whole mock WebSocket server.

Claude writes rules in plain words. You manage them in the Rules view.

**It works on office networks.** An upstream proxy carries every connection to the servers: HTTP, HTTPS, HTTP/2, tunnels and WebSockets. It can be an HTTP proxy that signs in with Basic or Windows NTLM credentials, SOCKS5, or a PAC file that picks per URL. The doctor offers the network's own proxy for it.

**It tells you what is wrong, and fixes it.** The [doctor](#the-doctor) checks the proxy, the system proxy, VPNs, other proxy apps, the CA on each client, pinned hosts, upstream failures and Android devices. Each finding names its fix, and many have a button. The proxy repairs some things on its own:
- **Pinned hosts** pass through after two refusals, so the app keeps working.
- **A system proxy left on** by a killed proxy is put back by a watchdog.
- **A self-signed dev server** gets its certificate accepted in one press, for that host only.

**It keeps Claude's context small.** Long URLs are cut, requests are read part by part, and bodies share one budget. `json_path` picks one field of a big body. `since` and `wait_for_request` replace polling.

**One proxy, every session.** A single proxy serves every Claude Code session on the Mac:
- A second session attaches and sees what the first recorded.
- Each project's rules apply while its session is open.
- The Health view shows the process, its memory and the sessions using it.

**It runs locally.**
- No account, no telemetry, no npm dependencies.
- Its CA is made on your machine.
- Recordings stay in `~/.claude/proxy-mod`.

## Tools for Claude

| Tool | What it does |
| --- | --- |
| `list_requests({ filter?, since?, limit? })` | The proxy's state and one line per request: id, method, status, URL (long ones cut), size, time, type, WebSocket and event counts, rules, error. `since` lists only what is new. |
| `get_request({ id, part?, json_path?, max_chars?, from?, limit? })` | One request, by part: `summary`, `headers`, `request`, `response`, `messages`, `all`. Bodies share one budget. JSON is compact when pretty would not fit, and `json_path` picks one field. gRPC, protobuf, trailers, WebSocket messages and events are included. |
| `search_requests({ text, where?, filter? })` | Which requests hold some text in their URL, headers, bodies, messages or events, with the text in context. |
| `wait_for_request({ filter, timeout_s?, until? })` | Waits for the request the person is about to trigger, and answers it the moment it ends. |
| `diff_requests({ a, b })` | What differs between two requests: method, URL, query, headers, status, JSON field by field. |
| `replay_request({ id, method?, url?, headers?, body?, json? })` | Sends a request again, as it was or changed, through the proxy, so it is recorded and rules apply. |
| `resume_request({ id, action?, changes?, respond? })` | Lets go of an exchange held at a breakpoint: as it was, changed (method, URL, headers, body, status), answered by hand, or cut. |
| `send_ws_message({ id, to, text \| json \| b64 })` | Injects a message into a live WebSocket, to the client or to the server. |
| `close_websocket({ id, code?, reason? })` | Closes a live WebSocket, to test reconnects. |
| `add_rule`, `update_rule`, `remove_rule`, `list_rules` | The rules file, applied at once. |
| `track_domains({ add?, remove?, set?, enabled? })` | Decrypt and record only the app's hosts, and see what passed through. |
| `export_har({ filter?, file? })` | HAR 1.2 with bodies and WebSocket messages, for a teammate or Chrome DevTools. |
| `diagnose()` | The doctor: every check, each finding with its fix. |

The plugin also ships three skills that Claude loads when the task calls for them:

- **`wirepane-debugging`:** the order that works, from filter to summary to part, then search, diff, replay and verify. Also how to read gRPC, WebSocket and SSE traffic cheaply.
- **`wirepane-troubleshooting`:** symptom, check, fix, for everything the doctor knows. It includes the fix in your own app: Android `network_security_config`, OkHttp and iOS pinning in debug builds, Flutter `HttpOverrides`, and proxy settings for Node, Go, Python, Java, Docker and Unity.
- **`wirepane-rules`:** recipes for mocks, latency, chaos, JSON rewrites, GraphQL operations and WebSocket mocks. Every one is tested to validate.

## The doctor

`/proxy doctor`, the **Health** view (`h`), or Claude's `diagnose` check:

| Check | Finds | Fix |
| --- | --- | --- |
| The proxy and its process | Stopped, failed, a port taken (and by whom; a Wirepane 0.7 proxy still running after an update); pid, uptime, memory, disk, sessions | Start again, Stop it and start, Restart |
| The system proxy | Left on by a dead proxy (no internet); held by Charles or Proxyman | Put back; Setup |
| VPN and other proxy apps | A `utun` default route; Charles, Proxyman, mitmproxy, HTTP Toolkit running | What to try |
| The CA on this Mac | Safari and Mac apps would refuse HTTPS | Trust on this Mac |
| Refusals per client | Every host refused: the CA is missing. One host among working ones: it pins its certificate | Setup for that client, or Never decrypt it |
| Pinned hosts | Passed through after two refusals (or an OkHttp-style close right after the handshake) | Decrypt them again once trusted |
| Upstream failures | DNS (`ENOTFOUND`), self-signed dev servers, closed ports, `localhost` confusion, unreachable networks | Accept its certificate; what to check |
| The network's own proxy | The system proxy pointed at an office's or a VPN's proxy before Wirepane took its place | Use it upstream |
| Tracked domains | A list that matches nothing that came, and what passed instead | Add the real hosts |
| Android devices | Not pointed at the proxy; apps that will not trust a user CA; a rootable image | Setup; Trust in all apps |

## Set up a client

| Client | How |
| --- | --- |
| A separate browser | **Setup → Browser → Open Google Chrome** (or Edge, Brave, Chromium). It starts a new instance with a profile of its own:<br>`--proxy-server`<br>`--proxy-bypass-list=<-loopback>`, so localhost is captured too<br>`--ignore-certificate-errors-spki-list`, so it trusts the proxy without the keychain<br>HTTP/2 and WebSockets work as they do anywhere. |
| iOS Simulator | **Setup → iOS**: **Use** (or **Boot & use**) boots one, adds the CA (`simctl keychain add-root-cert`) and turns on the macOS system proxy, since a simulator has no proxy setting of its own. |
| iPhone / iPad | **Setup → iOS → iPhone / iPad**:<br>1. **Listen on LAN**.<br>2. Scan the QR code to install the profile.<br>3. Turn on full trust under **Certificate Trust Settings**.<br>4. Set the Wi-Fi proxy to the address shown.<br>The section confirms when traffic arrives. |
| Android emulator | **Setup → Android → Emulator**: **Start through the proxy** launches an AVD with `-http-proxy` and opens the CA page in its browser.<br>Apps trust a user CA only with a `network_security_config`. On a Google APIs image, **Health → Trust in all apps** makes the CA a system CA until the next reboot. |
| Android phone | **Setup → Android → Phone**: on USB, **Point USB phones at the proxy** (`adb reverse`, no Wi-Fi needed); on Wi-Fi, **Listen on LAN**, the QR code, and the proxy setting shown. |
| Safari and Mac apps | **Setup → macOS → Turn on for this Mac** (Claude's hosts bypass it) and **Trust CA on this Mac**. Both are put back when the proxy stops. |
| curl, Node, Python, Go, Java, Docker | **Setup → CLI** copies `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`. The troubleshooting skill covers the clients that ignore the proxy. |

### Claude Code keeps working

Claude Code does not trust the proxy's CA, and with the system proxy on, its own traffic would come here. Two guards keep it whole:

- **Claude's hosts are bypassed.** Anthropic's and Claude's hosts are on the system proxy's bypass list, and the proxy never decrypts them anyway.
- **Claude's processes are tunnelled.** A local connection from a process that descends from Claude Code (the commands and MCP servers it runs, the Claude app) is tunnelled untouched.

## Rules

Rules change matching requests before they are sent, responses before the client gets them, and WebSocket messages both ways.

- **Writing them.** Ask Claude in plain words and it writes the rule. The **Rules** view (`r`) lists them in words, with hit counts. It turns them on and off, reorders them, and removes them.
- **Where they live.** In the project, in `.claude/proxy-rules.json`, so you can commit them. The file is reloaded the moment it changes.
- **Order.** The first rule applies first. Every matching rule applies in turn; `"stop": true` ends the chain.

```json
{
  "rules": [
    {
      "id": "slow-feed",
      "description": "The feed on a bad 3G line, failing now and then",
      "match": { "methods": ["GET"], "host": "api.example.com", "path": "/v1/feed*" },
      "request": [{ "type": "delay", "ms": 800, "msMax": 2500 }],
      "response": [{ "type": "throttle", "bytesPerSecond": 50000 }]
    },
    {
      "id": "mock-prices-socket",
      "description": "A price feed, with no server",
      "match": { "path": "/ws/prices" },
      "request": [{ "type": "respond", "status": 101 }],
      "messages": [
        { "type": "send", "on": "open", "to": "client", "json": { "type": "hello" } },
        { "type": "reply", "when": "\"subscribe\"", "json": { "type": "price", "price": 42.5 } }
      ]
    }
  ]
}
```

**Match.** Every condition given must hold:
- `url`, `host` and `path` take globs (`*.example.com`, `/v1/*`) or `re:<regex>`;
- `methods`, `headers`, `query` and `bodyContains`;
- on the response side, `status` (`404`, `4xx`, `>=400`, `500-599`) and `contentType`.

| Action | Request | Response |
| --- | :-: | :-: |
| `delay {ms, msMax?}`, `throttle {bytesPerSecond}` | ✓ | ✓ |
| `setHeader`, `removeHeader` | ✓ | ✓ |
| `setQuery`, `removeQuery`, `mapRemote {scheme?, host?, port?, path?}`, `replaceUrl` | ✓ | |
| `setBody {text \| json \| file}`, `replaceBody {pattern, with}`, `mergeJson {json}` | ✓ | ✓ |
| `respond {status, headers?, text \| json \| file}`: no server asked (101 on a WebSocket: a mock server) | ✓ | |
| `setStatus {status}` | | ✓ |
| `fail {kind: reset \| close \| timeout}` | ✓ | ✓ |
| `breakpoint {timeoutMs?}`: held until you (the Held view) or Claude (`resume_request`) let it go, changed or not; after its time (5 min) it goes on as it was | ✓ | ✓ |
| `script {code}` | ✓ | ✓ |

| WebSocket step (`messages`) | What it does |
| --- | --- |
| `direction: out \| in \| both`, `when: "text" \| "re:…"`, `on: open` | Which messages it takes (or once, as the socket opens) |
| `replaceMessage {pattern, with}`, `setMessage {text \| json \| file}`, `mergeJson {json}` | Change the message |
| `drop`, `delay {ms, msMax?}` | Lose it, or hold it |
| `reply {text \| json}` | Answer the sender; the message goes no further |
| `send {to, text \| json}` | One more message, to the client or the server |
| `close {code?, reason?}` | Close both sides |
| `script {code}` | `async (msg, ctx) => {}`: change `msg.text`, `msg.drop = true`, `ctx.send(to, …)`, `ctx.close(…)` |

**Bodies.** A response body is held back only when a rule changes it, so server-sent events keep streaming under header rules.

**Scripts.** A script runs only once its SHA-256 is approved. A rules file cloned with a repository cannot run code unasked; press **Allow script**. Scripts Claude adds through its tools are approved with them.

**In the list.** A request a rule changed is marked `✎`, and its detail says what each rule did. Filter with `is:modified` or `rule:<id>`.

## Filter

Terms separated by spaces must all hold; a leading `-` negates one. Free text matches a substring of the URL.

| Term | Matches |
| --- | --- |
| `method:POST`, `method:get,post` | the method |
| `status:404`, `status:4xx`, `status:>=400`, `status:500-599` | the response status |
| `host:api.example.com`, `host:*.example.com` | the host |
| `path:/v1/login` | a substring of the path |
| `type:json\|html\|xml\|js\|css\|img\|font\|media\|text\|form\|grpc\|ws\|tunnel\|other` | the content type |
| `is:error\|ok\|pending\|tunnel\|ws\|https\|h2\|grpc\|held\|rejected\|modified` | the state (`error` includes failed gRPC calls; `held`: waiting at a breakpoint) |
| `client:192.168.1.20`, `rule:slow-feed` | the client, a rule |

## Tracked domains

A phone talks to dozens of hosts. Turn on the tracking list and the proxy decrypts and records only your app's domains. Everything else passes through untouched and unrecorded.

```
/proxy track app.example.com *.example.com     track these (*.example.com covers example.com)
/proxy untrack app.example.com                 stop tracking one
/proxy untrack                                 every domain again
```

The **Domains** view (`d`) shows the hosts that passed through, busiest first, each with a **track** button. Clients that connect to an address (the Android emulator) are tracked by the name in their TLS handshake.

## One proxy for every session

The first session that needs the proxy starts it detached; the others attach to it.

- **What a session gets on attaching:** the requests recorded so far, the tracked domains, the hosts passed through, and the rules of its own project.
- **Sessions share the proxy:**
  - Each project's rules apply while its session is attached.
  - The tracked domains are the proxy's.
  - `/clear` and `--resume` keep everything in place.
- **When it stops:**
  - `/proxy stop` stops it for everyone and says how many other sessions it served.
  - A session that ends only lets go; the last one out stops it.
  - With every session gone, it waits 90 seconds, then puts the system proxy and Android devices back and exits.
- **New settings:** a proxy of another version or with other settings is replaced once nobody uses it. `/proxy restart` replaces it at once.

```
/proxy            open the pane and start (or attach to) the proxy
/proxy setup      set up a browser, iOS, Android, macOS or CLI client
/proxy doctor     the doctor's findings, and the Health view
/proxy rules      the rules
/proxy track      the tracked domains
/proxy export     write a HAR file (.claude/wirepane-<time>.har, or the path given)
/proxy restart    restart the proxy
/proxy stop       stop it (and point the system proxy and Android devices back)
/proxy clear      clear this session's list
/proxy status     one line about its state
/proxy tree|list  the requests as a tree (host → path) or a list
```

## Options

Set them in `/config`, or in `/plugin` → **Installed** → **wirepane** → **Configure options**.

| Option | Default | |
| --- | --- | --- |
| Proxy port | `8899` | |
| Proxy reachable from | `local` | `lan` opens it to phones on the network (never to this Mac's localhost) |
| Hosts never decrypted | `*.apple.com,*.icloud.com,*.mzstatic.com,*.apple-cloudkit.com` | tunnelled untouched; hosts that refuse the certificate twice are added on their own |
| Hosts with unchecked certificates | (none) | dev servers with self-signed certificates, by host |
| Upstream proxy (office, VPN) | (none) | an office's or a VPN's proxy every connection to a server goes through: `http://[user:password@]host:port` (Basic or NTLM, whichever it asks for; a Windows `DOMAIN\user` as `DOMAIN%5Cuser`), `socks5://[user:password@]host:port`, or a PAC file as `pac+http://[user:password@]host/proxy.pac` (the credentials go to the proxies it names, not to the PAC's server) |
| Hosts that skip the upstream proxy | (none) | hosts reached without the upstream proxy; this Mac's own addresses and `*.local` always are |
| Requests to keep | `2000` | |

## How it works

```
session A ──spawns──▶ node sidecar/attach.mjs ─┐                         ┌── browser
session B ──spawns──▶ node sidecar/attach.mjs ─┼─ events ─▶ node sidecar/proxy.mjs --daemon ◀── :8899 ── simulator
   pane · tools · status line                  └─ commands ─▶ (one per Mac, detached)  └── phone · emulator
                                                       │ headers, bodies, messages → ~/.claude/proxy-mod/flows/
                                                       │ watchdog: puts the system proxy back if it is killed
```

A mod runs sandboxed, with no sockets of its own, so the proxy is a small Node.js process.

- **TLS.** It terminates TLS with a certificate per host (397 days at most), signed by a CA made on your machine. ALPN gives each client HTTP/2 or HTTP/1.1 on its own, and each server too.
- **What reaches the mod.** Request summaries stream to the mod as JSON lines. Headers, bodies, WebSocket messages and events stay on disk until the pane or Claude reads them.

[docs/design.md](docs/design.md) has the details.

## What it runs and what it changes

Wirepane sends nothing of its own anywhere: no telemetry, no update checks, no downloads. It connects only to the servers the clients you point at it asked for. A request reaches Claude only when Claude calls a tool; what it reads then becomes part of the conversation, like a file Claude reads.

While the proxy is on, it runs:

- **The proxy:** `node sidecar/proxy.mjs --daemon` on `127.0.0.1` (on the network too in `lan` mode). It is detached so other sessions can use it, and stops when the last session leaves.
- **The session links:** `node sidecar/attach.mjs`, one per session, which passes the proxy's events to the mod.
- **The watchdog:** `node sidecar/watchdog.mjs`, which puts the system proxy back if the proxy is killed.
- **`openssl`:** makes the CA and the host certificates.
- **System tools:** `route`, `networksetup` and `scutil` find this Mac's addresses and read the system proxy. `ps` and `lsof` tell Claude's own connections apart. The doctor uses `ps`, `lsof` and `adb` too.

Only when you press the button for it:

| In the pane | Runs | Changes |
| --- | --- | --- |
| **macOS → Turn on for this Mac**, **iOS → Use** | `networksetup`, through `osascript` when macOS asks for an administrator | The system proxy, put back when the proxy stops |
| **macOS → Trust CA on this Mac** | `security add-trusted-cert`, which macOS asks you to confirm | The CA in your login keychain |
| **iOS → Use**, **Boot & use** | `xcrun simctl`, `open -a Simulator` | The CA in that simulator's keychain |
| **Browser → Open** | `open -na <browser>` with a profile of its own | Nothing outside `~/.claude/proxy-mod/browser` |
| **Android → Start through the proxy**, **Android → proxy**, **Point USB phones** | `emulator -http-proxy`, `adb shell settings put global http_proxy`, `adb reverse` | The device's proxy, put back by **Revert** and when the proxy stops |
| **Health → Trust in all apps** (Android) | `adb root`, `adb push`, a shell script that mounts a tmpfs over the system CA store | The emulator's system CAs, until it reboots |
| **Health → Accept its certificate**, **Never decrypt it** | Nothing | The plugin option, which restarts the proxy |
| **Install Node.js**, shown when no Node was found | `brew install node` | Node.js from Homebrew |

Files it writes:

- **`ca`, `certs`:** the CA (RSA-2048, the key readable by you only) and the certificates made from it.
- **`flows/<run>`:** the headers, bodies, WebSocket messages and events of recorded requests. They can hold the passwords, tokens and personal data of the apps you debug. A run's folder is deleted two days after its last use.
- **`sidecar.json`, `sidecar.log`:** where the running proxy is, and its log.
- **`tracking.json`, `trusted-scripts.json`:** the tracked domains, and the rule scripts you approved.
- **`system-proxy-backup.json`, `android-proxied.json`:** what to put back.
- **`<project>/.claude/proxy-rules.json`:** written once you or Claude add a rule.

All of these live in `~/.claude/proxy-mod` except the rules file, which lives in your project.

## Uninstall

1. Run `/proxy stop`. It puts back the system proxy and the Android devices, and stops the shared proxy.
2. Run `/plugin uninstall wirepane@wirepane`.
3. Remove the CA where you trusted it:
   - Keychain Access on the Mac (search for *Wirepane CA*);
   - **Settings → General → VPN & Device Management** on an iPhone;
   - user credentials on Android.
4. Run `rm -rf ~/.claude/proxy-mod` to delete the CA, the recordings and the browser profiles.

## FAQ

**Is it a replacement for Proxyman, Charles, mitmproxy or HTTP Toolkit?**
For "what did my app send, what came back, and why does it fail", yes, without leaving Claude Code. That covers HTTP/2, gRPC, WebSockets and SSE, with rules, mocks, replays and diffs, and it works behind an office proxy. What it does not have is in the [limits](#limits). Proxyman and HTTP Toolkit have MCP servers too. Wirepane is built around the agent: the doctor, the waiting, search and diff tools, the context budget, and the skills that fix the app's own code.

**Do I have to install the certificate on my Mac?**
Not for the separate browser, which trusts the proxy by SPKI hash. Safari, native Mac apps and the iOS Simulator need the CA. One press each.

**Why do some requests show `CERT`?**
The client refused the proxy's certificate. Either it does not trust the CA yet, or the app pins its certificates. `diagnose` tells which. A pinned host passes through after two refusals, so the app keeps working.

**I see nothing from my Flutter (or Go, or Unity) app.**
Some runtimes ignore the system proxy. The troubleshooting skill has the few lines that fix it in a debug build.

**Does my traffic leave my machine?**
Only to the servers it was going to anyway. Recordings stay in `~/.claude/proxy-mod`. Claude reads a request only through a tool.

**Does it capture Claude Code's own traffic, or the commands Claude runs?**
No. It captures the clients you point at it.

## Limits

- **HTTP/3 (QUIC)** is UDP and never meets an HTTP proxy. Chrome drops to HTTP/2 behind one; an app that forces QUIC is not seen.
- **Protobuf** is decoded without a schema: field numbers, not names.
- **WebSocket compression:** permessage-deflate is taken out of the client's offer. A server that insists on it may refuse; a compressed message passes on undecoded.
- **Kerberos:** an upstream proxy that takes only Kerberos tickets needs a helper that signs in for you, such as [Px](https://github.com/genotrance/px); point `upstreamProxy` at it. Basic and NTLM (also inside Negotiate) sign in by themselves.
- **Android system CA:**
  - It needs an emulator image that allows root: Google APIs, not Google Play.
  - It lasts until a reboot.
  - Android 17 asks for Certificate Transparency on system CAs, which Wirepane's certificates do not carry.
  - Chrome on Android trusts a user CA anyway.
- **Pinned apps:** someone else's app that pins its certificates stays encrypted; it is passed through.
- **Rule scripts** run in Node's `vm` module: approve only code you would run yourself.
- **Platform:** macOS only, on an early-access Claude Code API (mods).

## Development

```sh
claude plugin validate --strict .
claude plugin test .                         # the mod: logic, the pane (terminal and desktop), the tools
node --test --test-force-exit sidecar/*.spec.mjs   # the proxy against local HTTP/1.1, HTTP/2, gRPC and WebSocket upstreams
```

To run a working copy, use `claude --plugin-dir /path/to/wirepane`.

## License

[MIT](LICENSE). Not affiliated with Anthropic, Proxyman, Charles, mitmproxy or HTTP Toolkit.
