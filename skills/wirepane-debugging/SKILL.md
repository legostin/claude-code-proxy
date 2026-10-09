---
name: wirepane-debugging
description: Use when debugging an app's network traffic with Wirepane (the /proxy mod) - finding the failing API call, comparing a request that works with one that fails, reproducing or changing a request, waiting for a request the person is about to trigger, reading WebSocket, gRPC or server-sent events traffic. Covers the mcp__wirepane__* tools and how to use them without flooding the context.
---

# Debugging traffic with Wirepane

Wirepane is an HTTPS proxy inside Claude Code. It records what a browser, an iOS simulator or iPhone, an Android emulator or phone sends and gets back: HTTP/1.1, HTTP/2, gRPC, WebSockets and server-sent events. One proxy serves every Claude Code session on the Mac, so a request captured from another session is here too.

## The order that works

1. **Nothing shows, or the app fails behind the proxy?** Call `diagnose` first. It names the cause and the fix, for example a client without the CA, a pinned host, a system proxy held by Charles, a VPN, or a dev server with a self-signed certificate. Then follow the `wirepane-troubleshooting` skill.
2. **Find the request.** Call `list_requests` with a filter, never bare on a busy proxy:
   - `host:api.example.com is:error`
   - `method:POST path:/v1/login`
   - `type:json status:4xx`
   - `type:grpc`
   - `is:h2`
   - `-host:*.google.com` (a leading `-` negates a term)

   The answer ends with the newest id. Pass it as `since` next time to see only what is new.
3. **Is the person about to tap something?** Call `wait_for_request({ filter: "path:/v1/checkout" })` and tell them to go ahead. It answers the moment that request ends. Don't call `list_requests` in a loop.
4. **Read one request in steps:**
   - `get_request({ id, part: "summary" })`: status, timing, protocol, error, the rules that touched it.
   - `get_request({ id, part: "response" })`, or `part: "request"` / `part: "headers"`.
   - For a large JSON body, `json_path: "data.items[0]"` pulls one part. `max_chars` raises the 12000-character budget only when needed.
5. **Look across requests.**
   - `search_requests({ text: "invalid_token" })` finds a value in URLs, headers, bodies, WebSocket messages and events.
   - `diff_requests({ a, b })` compares the request that works with the one that fails: query, headers, status, JSON fields.
6. **Reproduce and test a fix in place.** Use `replay_request({ id, headers: { Authorization: "Bearer …" }, json: { … } })`. It really sends the request again. Ask before replaying anything that pays, posts, deletes or mails.
7. **Hold one request and change it live.** A rule with a `breakpoint` step pauses it. `get_request` shows what is held; `resume_request` lets it go, changed, answered by hand or cut. Use it to see how the app copes with an edited answer before you write a mock.
8. **Change the traffic without touching the server.** Use `add_rule`: mock a response, delay, throttle, fail, rewrite a body, map to a local server, rewrite WebSocket messages, or play a WebSocket server. The `wirepane-rules` skill has the recipes.
9. **Fix the code, then prove it.** Call `wait_for_request` again for the same request and check its status and body.

## Protocols

- **gRPC.** Bodies are decoded without a schema, by field number: `1: "hi"`, nested messages indented. A failed call shows `gRPC NOT_FOUND: …` from its trailers. To name the fields, look for the `.proto` files in the repo (`rg -g '*.proto' 'service Greeter'`) and map the numbers.
- **WebSocket.**
  - `get_request({ id, part: "messages" })` lists the messages both ways with their timing: `→ server` is client to server, `← client` the other way. Page with `from` and `limit`; `from: n, limit: 1` shows one message in full.
  - Binary messages show what they hold, read without a schema like gRPC bodies: `protobuf after its length: 1: 13 2: 2 3 { 1: "…" }`, `protobuf`, `gzip, text`. Name the fields from the repo's `.proto` files. Base64 means no reading fit (MessagePack, CBOR, a custom format, or compression Wirepane could not take out).
  - `send_ws_message({ id, to: "client" | "server", text | json })` injects a message into the live socket.
  - `close_websocket({ id, code: 1011 })` tests how the app reconnects.
- **Server-sent events** (LLM streaming APIs). `get_request` lists the events with the milliseconds at which each one arrived. Use it for slow first tokens, dropped streams and malformed `data:` lines.

## Keep the context small

- Filter first. `list_requests` caps at 200 lines, and long URLs are cut.
- Read the summary first, then one part. Use `json_path` for big JSON.
- `export_har` writes everything to a file for a teammate or a bug report, instead of pasting it.
- Never paste tokens or personal data from captures into commits or issues.
