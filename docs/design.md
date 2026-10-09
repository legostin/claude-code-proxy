# Wirepane (first named proxy): Proxyman inside Claude Code

Date: 2026-10-07. Status: approved and built.

## Goal

A Claude Code mod that runs a MITM HTTP(S) proxy for outside clients (a
browser, the iOS Simulator or an iPhone, the Android emulator or a phone),
makes the certificates, shows setup guides, and lists the captured requests
with a filter. Claude reads the same traffic through tools.

Out of scope for v1: proxying the Bash commands Claude runs, Claude Code's
own traffic, switching the macOS system proxy automatically, HTTP/2 and gRPC,
decoding WebSocket frames, breakpoints and rewrites, a QR code. (0.2 added
the QR code, 0.3 rewrite rules.)

## 0.8 (2026-10-09): every protocol, one proxy for every session, a doctor

What follows this section describes 0.1-0.7. Where 0.8 differs, this section wins.

**Processes.**

```
session ──$.process.spawn──▶ attach.mjs ── GET /__wirepane/<token>/events ──▶ proxy.mjs --daemon ◀── :8899 ── clients
session ──$.process.spawn──▶ attach.mjs ──┘   (JSON lines: what it holds, then live)   │ registry <data>/sidecar.json
                                                                                        └▶ watchdog.mjs (system proxy back after a kill -9)
```

- `attach.mjs` finds the daemon in the registry and asks it `info`. When there is none, it starts the daemon detached, under `<data>/sidecar.lock`, and waits for it to answer. A daemon of another version or other settings, with no session attached, is replaced.
- The daemon sends an attaching session a `ready` event, then:
  - what it holds: the last 2000 flows, the tracked domains, the skipped hosts, the network, the rules events, the pinned hosts;
  - then every event as it comes.
- With no session attached for `--linger-ms` (90 s), the daemon puts back the system proxy and the Android devices listed in `<data>/android-proxied.json`, then exits.
- Rules come one file per attached session's project. A rule keeps its own project root (`__root`) for `file` bodies.
- The tracked domains are the proxy's: `<data>/tracking.json`, written by any session. A session that starts the daemon writes its own list there.
- The mod's session end kills only its `attach.mjs` when others are attached; the last session stops the daemon. `/proxy stop` stops it for everyone.

**Control** (`POST /__wirepane/<token>/<command>`, local clients only, the token in `ready`):

- `info`;
- `stop`;
- `events`;
- `flows/wait {after, until, timeoutMs}`: a long poll, so the mod's `wait_for_request` spends no hook budget;
- `flows/clear`;
- `tracking/set`;
- `ws/send`, `ws/close`, `ws/list`;
- `pinned/list`, `pinned/clear`.

The mod reaches these with `curl` through `$.process.run`.

**Protocols.**

- **HTTP/2.** The decrypted socket offers ALPN `h2, http/1.1`. An h2 client gets an `http2.createServer()` of its own per connection.
  - A hand-made server-side `TLSSocket` never clears `secureConnecting`, which would make an HTTP/2 session wait forever, so it is cleared by hand.
  - Pseudo-headers stay out of the pairs; `:authority` becomes `host`.
  - Upstream, an h2 client gets an h2 session per origin and client locality when ALPN says the server speaks h2 (learned once per origin), and HTTP/1.1 otherwise.
  - Trailers are forwarded to h2 clients and recorded (`resTrailers`). `te: trailers` is kept for gRPC.
  - A rule's `fail: reset` resets the stream; `close` ends the session.
- **gRPC and protobuf.** `sidecar/protobuf.mjs` splits the 5-byte frames (gunzipping compressed ones, reading gRPC-Web's trailer frame and its base64 text form) and decodes protobuf without a schema. The result is written beside the body as `<id>.<side>.view`. `grpcStatus` and `grpcMessage` come from the trailers.
- **WebSockets** (`sidecar/websocket.mjs`).
  - The upgrade's request rules apply. `respond {status: 101}` makes Wirepane the server: it computes `Sec-WebSocket-Accept`, echoes the first subprotocol, and answers pings and closes.
  - permessage-deflate is taken out of the offer.
  - The client gets the server's own 101 head.
  - Frames are read both ways. Without a message rule each frame goes on at once as it came; with one, data frames are held until the message is whole, the steps apply, and the message goes on as it came or encoded anew (masked toward the server).
  - Control frames pass at once; closes queue behind held messages.
  - Unreadable bytes switch that direction to a raw copy.
  - The record is `<id>.ws.jsonl`: `{t, dir, op, size, text | b64, code?, note?, was?}`, capped at 20000 lines. Messages are cut at 64 KB, binary at 4 KB of base64.
  - `wsOut` and `wsIn` count data messages; flow updates are throttled to two a second.
- **Server-sent events** (`sidecar/sse.mjs`). `text/event-stream` responses without content encoding are parsed as they stream, into `<id>.sse.jsonl` `{t, event?, id?, data, retry?}`, with `sseEvents` on the flow.
- **Plain HTTP inside CONNECT.** A browser's `ws://` arrives that way. It goes to the inner HTTP/1.1 server with scheme `http`, so it is recorded like any request.

**Certificate refusals.** Keyed by client and host:
- an alert counts 1;
- a handshake closed within 1.5 s with no request counts ½ (OkHttp's pin mismatch);
- at 2 the host is passed through (`pinned`, tunnel rows with note `pinned`).

An entry made while that client had accepted no handshake at all is blind: the client lacks the CA, it does not pin. Blind entries go the moment the client accepts one. Handshakes the client resets (`ECONNRESET`: a browser dropping a preconnect) get no row.

**Upstream certificates.** They are checked unless the host is in `--insecure-hosts`, where an agent and sessions of their own skip the check.

**Upstream proxy** (`sidecar/upstream.mjs`, `--upstream-bypass`). `--upstream-proxy` takes three forms:
- `http://[user:pass@]host:port`: CONNECT, and plain HTTP in absolute form;
- `socks5://[user:pass@]host:port`: RFC 1928 and 1929, names resolved by the proxy;
- `pac+URL`: the file's `FindProxyForURL` runs in a `vm` sandbox with the standard helpers. DNS goes in two passes: names it asked for are looked up, then it runs again. The routes it answers are tried in order, `DIRECT` included. Every connection to a server goes through it, except this Mac's own addresses (`localhost`, `127.*`, `::1`, `*.local`) and the bypassed hosts:
- HTTPS agents: `createConnection` that CONNECTs first, then TLS;
- HTTP/2 sessions;
- plain HTTP, in absolute form with `Proxy-Authorization`;
- recorded and quiet tunnels (`dial`);
- WebSocket and raw upgrades (`openServerSocket`).

A refusal (a 407 says it wants credentials) is the flow's error, code `EUPSTREAMPROXY`. The doctor offers the proxy the network service had before Wirepane (from the backup, or the system proxy now) as the upstream.

**The mod.**
- **New modules:**
  - `hooks/model.ts`: budgets, URL cutting, JSON for the model, `jsonPath`.
  - `hooks/diff.ts`: `diffRequests`.
  - `hooks/har.ts`: HAR 1.2, with Chrome's `_webSocketMessages`.
  - `hooks/doctor.ts`: findings from facts; the facts are gathered in `register.tsx`.
  - `hooks/android.ts`: the system CA script.
- **New tools:** `search_requests`, `wait_for_request`, `replay_request` (curl through the proxy with `x-wirepane-replay: <id>`, which the proxy strips and records as `replayOf`), `diff_requests`, `export_har`, `send_ws_message`, `close_websocket`, `diagnose`.
- **Changed tools:** `list_requests` takes `since` and caps at 200. `get_request` takes `part`, `max_chars` and `json_path`.
- **The pane:** the Health view (`h`) with the findings, a fix button where Wirepane can do it, and the proxy process (pid, uptime, memory, disk, sessions, open WebSockets, pinned hosts). Commands `/proxy doctor`, `restart` and `export`.
- **Skills:** `skills/wirepane-debugging`, `skills/wirepane-troubleshooting` and `skills/wirepane-rules`. `sidecar/skills.spec.mjs` validates every rule recipe in them.

## Architecture

```
mod (sandbox) ──$.process.spawn──▶ node sidecar/proxy.mjs ◀── :8899 ── clients
      ▲                                │ stdout: JSON-line summaries
      │ batched every 200 ms → $.state  │ headers/bodies → <data>/flows/<run>/<id>.{json,req,res}
      │                                 │ openssl → <data>/ca, <data>/certs
   pane + status line + tools (details read from disk with $.fs.read)
```

`<data>` is `~/.claude/proxy-mod`.

- A mod cannot open sockets, so the proxy is a dependency-free Node process
  the mod starts with `$.process.spawn` for the session's life.
- stdout carries short summaries only; full headers and bodies stay on disk.
- It starts on request (`/proxy`, `/proxy start`), never by itself, so two
  sessions do not fight over the port. "Wanted running" lives in `$.state`
  and survives a hot reload of the mod, which starts the sidecar again.

## The sidecar (`sidecar/proxy.mjs`, `sidecar/certs.mjs`)

- An HTTP proxy: absolute-form requests are proxied; `CONNECT` for HTTPS is
  terminated with a `tls.TLSSocket` and an `SNICallback`, offering ALPN
  `http/1.1` only. Upstream certificates are verified as usual.
- `CONNECT` to a host in `noDecrypt` is a plain tunnel, one row in the list
  (`CONNECT host:443`, bytes, duration). Apple's pinned domains are the default.
- A client that drops the TLS handshake on our certificate gets a row of its
  own: "the client refused the proxy's certificate (CA not trusted, or pinning)".
- Bodies stream to the client as they come (SSE works) and are copied to
  disk up to 3 MB, decoded (gzip, br, deflate, zstd) for reading.
- WebSocket and other upgrades: raw sockets piped, one `101` row.
- A direct (origin-form) request to the port, or any request to
  `http://claude.proxy/`, gets the setup page and the CA: `/` (HTML),
  `/ca.pem`, `/ca.crt` (DER), `/ca.mobileconfig`.
- Certificates: the CA is RSA-2048, CN "Wirepane CA (<host>)",
  825 days, key mode 0600. Leaves share one key, one certificate per host
  (SAN DNS or IP, 365 days, serverAuth), cached on disk, one issue per host
  however many connections ask at once.
- stdout protocol (JSON lines): `ready`, `flow` (a summary, repeated as it
  progresses), `fatal` (e.g. the port is taken), `log`.
- Summary: `id, ts, kind (http|tunnel|ws), method, scheme, host, port, path,
  status, reqSize, resSize, durationMs, contentType, state, error, errorCode,
  client`.

## The mod

Files: `hooks/register.tsx` (hooks, sidecar control, pane, state atoms),
`hooks/flows.ts` (pure logic: line protocol, merge, filter, formats),
`hooks/setup.ts` (the setup tabs' texts and commands), `types/index.d.ts`
(the state contract).

Options (`userConfig`): `port` (8899), `listen` (`local` | `lan`),
`noDecrypt` (comma-separated), `maxFlows` (2000), `node` (`node`).

Command `/proxy [start|stop|clear|setup|status]`: with no argument it opens
the pane and starts the proxy.

The pane has three views:
1. The list: a header `● 127.0.0.1:8899 · 342 requests` (`27 of 342 requests
   match` under a filter), [Stop/Start] [Clear] [Setup], the filter field,
   rows `401 POST https://api.x.com/v1/login 1.2KB 180ms`, newest first.
2. Detail: the request line, request and response headers, bodies as `Code`
   (JSON pretty-printed), [Back] [Copy as curl] [URL] [To prompt].
3. Setup, in tabs [Browser] [iOS] [Android] [macOS / CLI]:
   - Browser: an [Open <browser>] button per Chromium browser found (Chrome,
     Chrome Canary, Chromium, Edge, Brave), started with its own
     `--user-data-dir`, `--proxy-server`, `--proxy-bypass-list=<-loopback>`
     and `--ignore-certificate-errors-spki-list=<SPKI of the leaf key and
     the CA>`, so nothing goes into the keychain. Firefox as text.
   - iOS: [CA → simulators] (`xcrun simctl keychain <udid> add-root-cert`
     for every booted simulator), iPhone steps (Wi-Fi proxy, `.mobileconfig`,
     certificate trust). The simulator uses the macOS system proxy: copyable
     `networksetup` commands to turn it on and off.
   - Android: [Android → proxy] (an emulator gets `10.0.2.2:<port>`, a USB
     device `adb reverse` and `127.0.0.1:<port>`), [Revert] (`:0`, also done
     on stop and at session end), [Open CA page], phone steps, a
     `network_security_config` snippet.
   - macOS / CLI: `security add-trusted-cert`, `networksetup` on and off,
     curl, environment variables for Node, Python and Go.

Status line: `⇄ proxy :8899 · 342`.

Filter (shared by the pane and the tools): terms separated by spaces must
all hold, a leading `-` negates one; free text is a substring of the URL;
`method:`, `status:4xx`, `status:>=400`, `status:400-499`,
`host:*.example.com`, `path:`, `type:json|html|xml|js|css|img|font|media|text|form|ws|tunnel|other`,
`is:error|ok|pending|tunnel|ws|https|rejected`, `client:`.

Tools: `mcp__wirepane__list_requests({ filter?, limit=50 })`, the proxy's state
and a table; `mcp__wirepane__get_request({ id, max_body_chars=20000 })`, headers
and decoded bodies, cut to length.

## Errors

The port is taken, `node` or `openssl` is missing, the sidecar exits (the
tail of its stderr in the pane, [Start] again), the upstream is unreachable
(an error row in the list).

## Tests

- `claude plugin test`: the filter, line reassembly, the merge, curl, the
  pane on `terminal` and `desktop` (a row opens its detail, the setup tabs),
  the tools, with the sidecar and the disk stood in by test hooks.
- `node --test sidecar/proxy.spec.mjs`: the proxy on a random port with
  local HTTP and HTTPS upstreams, driven by curl: JSON-line events, body
  files, a refused certificate, the CA pages, tunnels, a taken port, and the
  loopback guard for network clients.

## What changed while building it

- The engine follows `$` only into functions of the hooks module's own file,
  and reads `$.state` atoms only from that file's consts. So sidecar control,
  the pane and the atoms live in `hooks/register.tsx`; separate modules hold
  pure logic only (`hooks/flows.ts`, `hooks/setup.ts`).
- `lan` mode: clients from other machines may not reach loopback targets (by
  literal, by `localhost`, and by what a name resolves to), and have
  connection pools of their own; otherwise the proxy would open this Mac's
  local services to the network. Such rows are marked `forbidden`.
- Android over USB: `adb reverse tcp:<port>` and a `127.0.0.1:<port>` proxy,
  so no Wi-Fi is needed.
- Stopping the sidecar: `kill <pid>` (the pid comes with `ready`). The
  sidecar exits by itself when its parent dies (its ppid becomes 1).
- Laid out like `secret-guard`: the mod folder is its own marketplace, with
  `tsconfig.json`, `.gitignore`, MIT, CI (validate, test, sidecar tests on
  macOS) and an English README.
- Checked live: headless Chrome with `--ignore-certificate-errors-spki-list`
  went through the proxy over HTTPS with no CA in the keychain.
- UI, comments and docs are all in English.

## 0.2.0

- The address to enter: `sidecar/network.mjs` ranks this machine's IPv4
  addresses for a phone (the default route's interface unless it is a VPN;
  VPN tunnels, VM and container bridges and link-local addresses last),
  labels them by hardware port (`Wi-Fi (en0)`), and the sidecar reports a
  change as a `network` event. Each setup tab lists every client with the
  exact server and port (`proxyTargets`), and **Listen on LAN** switches the
  option through `$.config.set`.
- A QR code of `http://<address>:<port>/` on the iOS and Android tabs while
  listening on the network: `hooks/qr.ts`, a dependency-free encoder (byte
  mode, level M, versions 1 to 10), drawn as a `Raster` of half blocks on the
  terminal and as `Svg` elsewhere. Verified with the jsQR decoder.
- A tree view of the list: origin → path segments → requests, single-child
  chains folded, request and failure counts per node, open nodes kept in
  `$.state`.

## 0.3.0: the rules engine

- **File.** `<project>/.claude/proxy-rules.json`, `{ "rules": [...] }`; the
  array's order is the priority. The sidecar gets its path (`--rules`) and
  watches it, and the trust file (`--trust`), with `fs.watchFile`; a change
  applies to the next request and is reported as a `rules` event.
- **Shared half.** `shared/rules.mjs`, plain JavaScript imported by both the
  sidecar and the hooks module: validation with sentences per field,
  request and response matching, and the one-line description the pane and
  the tools show. Patterns are globs, or `re:<source>`; `/source/flags` was
  dropped because every path starts with a slash.
- **Applying half.** `sidecar/engine.mjs`. The request side runs the
  matched rules' actions in order on `{ target, headers, body }`; the body
  is read whole only when a rule matches on it or changes it. `respond`
  answers without the server, `fail` resets, closes or holds the
  connection (a reset goes to the TCP socket beneath a TLS one). The
  response side picks the rules whose response conditions hold; the body is
  held back and decoded only when an action changes it, so header- and
  status-only rules keep responses streaming. `stop` ends the chain.
- **Scripts** run in `node:vm` (one second for the synchronous part, five in
  all) and only when the SHA-256 of their code is in
  `<data>/trusted-scripts.json`: approved in the Rules view, or by Claude's
  `add_rule`/`update_rule`, which go through Claude Code's permissions.
  `vm` is not a security boundary; the approval is.
- **Record.** A flow carries `rules` (ids, in order); its detail file
  carries `ruleLog`, and headers and bodies as the server and the client
  got them. The list marks such rows `✎`; the filter takes `is:modified`
  and `rule:<id>`.
- **Mod.** The Rules view (`/proxy rules`, `r`): order, on/off, ↑ ↓, ✕ (asks once more),
  description, the generated summary, errors, hit counts, Allow script.
  Edits rewrite the file through `$.fs.write`. Tools: `list_rules`,
  `add_rule`, `update_rule`, `remove_rule`; the rule's JSON schema rides
  in the tools' input schema, past the 2,048-character description limit.

## 0.4.0: tracked domains

- Per session `{ enabled, patterns }`: `$.state`, `$.store` under
  `tracking:<session id>` (back with `--resume`), and
  `<data>/sessions/<id>/tracking.json`, which the sidecar watches
  (`--tracking`). Off or empty, every host is tracked.
- Host patterns (`shared/rules.mjs`): globs over the host, `*.example.com`
  covering the apex, or `re:<regex>`; `normalizeHostPattern` cuts a typed
  URL or `host:port` to the host.
- Untracked HTTPS is a plain tunnel with no MITM and no record; untracked
  HTTP and WebSocket upgrades are passed through, never recorded, never
  touched by rules. The sidecar counts them per host and sends the counts
  (`skipped`) every two seconds while they change; the Domains view offers
  each host, and its `*.domain`, to track.

## 0.5.0: setup in one press, and Claude Code left whole

- **The self guard** (`sidecar/selfguard.mjs`). Claude Code trusts no CA of
  ours. Anthropic's and Claude's hosts are never decrypted. While `scutil
  --proxy` shows the system proxy pointing at this proxy (checked every
  three seconds, and at once when the mod writes its backup), a local
  CONNECT is traced to its process (`lsof -Fpn` on the client port, then the
  `ps -o args=` tree); one that descends from `claude` (the native build, the
  app, its daemon and pty hosts) or from node running
  `@anthropic-ai/claude-code` is tunnelled. Checked end to end with a shell
  named `claude` and an orphaned curl.
- **The system proxy** (`shared/systemproxy.mjs`). The service is the one
  the default route leaves by. Its web, secure-web and bypass settings are
  kept in `<data>/system-proxy-backup.json` before the change; the bypass
  list gains Claude's hosts. Put back on stop, at the session's end, and by
  the sidecar when its parent becomes launchd. networksetup runs as the
  user (it needs no administrator on this Mac), with one `osascript`
  administrator dialog as the fallback.
- **Devices.** iOS: `simctl list devices available -j`, booted first, then
  the newest runtime; **Use** boots (`simctl boot`, `bootstatus -b`), opens
  Simulator, adds the CA and turns the system proxy on. Android: `emulator
  -list-avds`, running ones matched through `adb emu avd name`; **Start
  through the proxy** runs the AVD with `-http-proxy` in the background.
  macOS: whether the keychain trusts the CA (`security verify-cert`), and
  **Trust CA on this Mac** (`security add-trusted-cert`, the system's own
  dialog).
- **Layout.** Each setup tab leads with its one-press path, then a framed
  section for a phone (the exact address, Listen on LAN, the QR code), then
  the CA and the guide.

## 0.6.0: where you land

- **Quick start.** An empty list is a framed set of one-press ways in, from
  what this Mac has: Start, open the first Chromium browser, use the first
  simulator, start the first AVD not running, set up a phone, track domains.
  Opening the pane looks for simulators and emulators in the background.
- **Sub-tabs.** iOS and Android split into the virtual device (simulator,
  emulator) and the real one (iPhone, an Android phone on USB or Wi-Fi).
- **The phone section** always shows the QR code once an address is known,
  and says Listen on LAN comes first while the proxy listens locally. It
  confirms traffic from each network client and counts the times a client
  refused the certificate. Listen on LAN finds its `/config` row through
  `$.config.list()` rather than assuming its key.
- **Android emulators** started from the tab are found by AVD name once up,
  waited for (`sys.boot_completed`) and shown the CA page in their browser.
- **Version.** The pane, the setup footer and `/proxy status` name the mod's
  version, so a session running an older copy is plain to see.
- **Testing through the proxy from Claude.** While the system proxy points
  here, Claude's own commands are tunnelled, curl included: a check of a
  rule from Claude's shell uses a process outside Claude's tree.
