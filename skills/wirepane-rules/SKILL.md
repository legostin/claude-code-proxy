---
name: wirepane-rules
description: Use when changing an app's traffic with Wirepane rules (mcp__wirepane__add_rule) - mocking an endpoint, adding latency or slow-network throttling, injecting errors and dropped connections for chaos testing, rewriting JSON, adding headers, sending requests to a local server, matching GraphQL operations, and WebSocket rules (rewrite, drop, answer, mock a whole WebSocket server). Recipes as rule JSON that validates.
---

# Wirepane rules

A rule matches requests and changes them before they are sent, their responses before the client gets them, and WebSocket messages both ways.

- **Where they live.** Rules live in `<project>/.claude/proxy-rules.json`, so they can be committed.
- **Applying them.** `add_rule` applies a rule at once. `update_rule` turns one on or off, moves it in the order or replaces its fields. `remove_rule` deletes one. The person can do the same in the Rules view (`/proxy rules`).
- **Order and chaining.** The first rule applies first. Every matching rule applies in turn; `"stop": true` ends the chain.
- **Patterns.** A glob (`*` is any run, `?` is one character, case aside, matched whole) or `re:<regex>`.
- **HTTP/2 and gRPC.** Rules work on them the same way.
- **Scripts.** A script Claude adds through `add_rule` is approved to run. One written in the file by hand waits for **Allow script** in the Rules view.

Prefer declarative steps to scripts. Give every rule a `description` the person will understand.

## Mock an endpoint

```json
{
  "id": "mock-profile",
  "description": "The profile screen without the backend",
  "match": { "methods": ["GET"], "host": "api.example.com", "path": "/v1/profile" },
  "request": [{ "type": "respond", "status": 200, "json": { "id": 7, "name": "Tess", "plan": "pro" } }]
}
```

A file from the project instead: `{ "type": "respond", "status": 200, "file": "fixtures/profile.json" }`.

## Latency, slow networks, timeouts

```json
{
  "id": "slow-feed",
  "description": "The feed on a bad 3G line",
  "match": { "path": "/v1/feed*" },
  "request": [{ "type": "delay", "ms": 800, "msMax": 2500 }],
  "response": [{ "type": "throttle", "bytesPerSecond": 50000 }]
}
```

Rough rates in bytes per second: Edge 25000, 3G 50000-100000, slow 4G 400000.

Never answer, so the app's timeout shows: `{ "type": "fail", "kind": "timeout" }`. Reset the connection: `"kind": "reset"`.

## Errors and chaos

```json
{
  "id": "login-500",
  "description": "Login fails on the server",
  "match": { "methods": ["POST"], "path": "/v1/login" },
  "request": [{ "type": "respond", "status": 500, "json": { "error": "internal" } }]
}
```

```json
{
  "id": "expired-session",
  "description": "Every API call answers 401, as an expired session does",
  "match": { "host": "api.example.com", "status": "2xx" },
  "response": [{ "type": "setStatus", "status": 401 }, { "type": "setBody", "json": { "error": "token_expired" } }]
}
```

`match.status` and `match.contentType` are known only from the response, so such a rule takes response steps only.

## Change a real response

```json
{
  "id": "feature-flag-on",
  "description": "The new checkout, whatever the server says",
  "match": { "path": "/v1/config" },
  "response": [{ "type": "mergeJson", "json": { "features": { "newCheckout": true } } }]
}
```

`replaceBody` with a literal or `re:` pattern (`$1` works in `with`) does the same for text.

## Headers, auth, local servers

```json
{
  "id": "staging-auth",
  "description": "A staging token on every API request",
  "match": { "host": "*.example.com" },
  "request": [{ "type": "setHeader", "name": "Authorization", "value": "Bearer staging-token" }]
}
```

```json
{
  "id": "api-to-local",
  "description": "The v2 API from the dev server on this Mac",
  "match": { "host": "api.example.com", "path": "/v2/*" },
  "request": [{ "type": "mapRemote", "scheme": "http", "host": "localhost", "port": 3000 }]
}
```

## Breakpoints: hold it, look, change it, let it go

```json
{
  "id": "pause-checkout",
  "description": "Hold checkout before it is sent and its answer before the app gets it",
  "match": { "methods": ["POST"], "path": "/v1/checkout" },
  "request": [{ "type": "breakpoint" }],
  "response": [{ "type": "breakpoint", "timeoutMs": 120000 }]
}
```

- **What is held.** A matching request stops before it is sent (or its response before the client gets it). It shows as `HELD` in `list_requests`, and `get_request` shows what is held. The person sees it in the Held view (`⏸ 1 held` in the pane).
- **Letting it go.** `resume_request({ id })` lets it go as it was.
  - `changes: { method?, url?, headers?, body? | json? }` changes the request; `changes: { status?, headers?, body? | json? }` changes the response.
  - `action: "respond"` with `respond: { status, text | json }` answers the request without the server.
  - `action: "abort"` cuts it.
- **Timing.** After `timeoutMs` (default 5 minutes) it goes on as it was. Tell the person to trigger the request, then use `wait_for_request({ filter: "is:held", until: "start" })` to catch it.

## GraphQL: one operation

```json
{
  "id": "graphql-login-error",
  "description": "The Login mutation answers a GraphQL error",
  "match": { "path": "/graphql", "bodyContains": "\"operationName\":\"Login\"" },
  "request": [{ "type": "respond", "status": 200, "json": { "errors": [{ "message": "Invalid credentials" }] } }]
}
```

## WebSockets

`match` matches the upgrade request. `messages` steps act on each message:

- **Which messages:** `direction` is `out` (client to server), `in` (server to client) or `both`. `when` is text the message holds, or `re:<regex>`.
- **What they do:** `replaceMessage`, `setMessage`, `mergeJson`, `drop`, `delay`, `reply` (answers the sender; the message goes no further), `send` (one more message, `to` client or server), `close`, `script`.
- **On open:** `on: "open"` runs a step once, as the socket opens.

```json
{
  "id": "chat-chaos",
  "description": "Hide secrets, answer pings locally, drop every typing event, slow the server down",
  "match": { "path": "/chat" },
  "messages": [
    { "type": "replaceMessage", "direction": "out", "pattern": "re:\"token\":\"[^\"]+\"", "with": "\"token\":\"[hidden]\"" },
    { "type": "reply", "direction": "out", "when": "\"type\":\"ping\"", "json": { "type": "pong" } },
    { "type": "drop", "when": "\"type\":\"typing\"" },
    { "type": "delay", "direction": "in", "ms": 500 }
  ]
}
```

Wirepane plays the WebSocket server itself, with no server needed: `respond` with status 101.

```json
{
  "id": "mock-prices-socket",
  "description": "A price feed that answers subscriptions",
  "match": { "path": "/ws/prices" },
  "request": [{ "type": "respond", "status": 101 }],
  "messages": [
    { "type": "send", "on": "open", "to": "client", "json": { "type": "hello", "version": 2 } },
    { "type": "reply", "when": "\"subscribe\"", "json": { "type": "price", "symbol": "ACME", "price": 42.5 } }
  ]
}
```

Test the app's reconnect: `{ "type": "close", "direction": "in", "when": "re:^\\{\"type\":\"price\"", "code": 1011, "reason": "server restart" }`, or `close_websocket` from a live session.

## Scripts, when nothing declarative fits

A request or response script is the body of `async (req, res, ctx) => {}`:

- It may change `req.method`, `req.url`, `req.headers` (lower-case names) and `req.body`.
- `req.respond = { status, headers, body }` answers the request without the server.
- It may change `res.status`, `res.headers` and `res.body`.
- `req.json()` and `res.json()` parse the bodies.

```json
{
  "id": "sign-requests",
  "description": "Adds the timestamp header the staging gateway checks",
  "match": { "host": "gateway.example.com" },
  "request": [{ "type": "script", "code": "req.headers['x-timestamp'] = String(Date.now())" }]
}
```

A message script is the body of `async (msg, ctx) => {}`:

- `msg.text` can be changed; `msg.json()` parses it.
- `msg.drop = true` drops the message.
- `ctx.send('client' | 'server', textOrObject)` sends one more; `ctx.close(code, reason)` closes the socket.

## Checking a rule

`add_rule` answers the rule in words, and the Rules view lists it with its hit count. Requests a rule changed are marked `✎` in the list. Their detail starts with what the rule did. `list_requests` shows `rules: <id>`, and `is:modified` filters them.
