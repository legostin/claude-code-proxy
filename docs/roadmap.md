# Wirepane roadmap

What comes next, in order. Each item says what changes for the person using it, then how it could be built.

## Next: one proxy, a request list per session

**Today.** Every Claude Code session on the Mac shares one proxy and one list. A second session attaches and sees everything the first recorded: its requests, its tracked domains, the hosts that passed through. Clear in one session clears the list for all of them.

**Next.** The proxy stays one: one port, one CA, one process, one capture on disk. Each session gets its own list.

- **What a session sees.** By default, the requests that arrived after it attached and that match its own scope. A **Show all sessions** switch in the pane (and `scope: "all"` in the tools) shows the whole capture.
- **The scope of a session.** Possible pieces, to settle in the design:
  - its own tracked domains (today tracking is one global list in `~/.claude/proxy-mod/tracking.json`);
  - the clients it claims, such as "this session is the iOS Simulator, that one is the Android emulator";
  - its project's rules: requests its rules changed always belong to it.
- **Claude's tools.** `list_requests`, `search_requests`, `wait_for_request`, `diff_requests` and `export_har` work on the session's own list. `get_request` and `replay_request` still reach any id, so a request one session points to can be opened from another.
- **Clear** clears this session's list only. The capture on disk is kept for the others and goes as it does today (two days after its last use).
- **Health** lists each attached session with its scope and how many requests it holds.

**How.**

- The sidecar tags each flow, as it is recorded, with the sessions whose scope it matches. The `flow` event carries the tags, and the backlog a session gets on attach is filtered by them.
- A session's scope must survive `/clear`: the session id changes then, and `$.state` resets. It has to be keyed by something that stays, such as the project folder, or carried over by `reattach`, which already follows the id change.
- The tests: two attached sessions with different scopes see different lists; `/clear` keeps the scope; Clear in one leaves the other's list whole; Show all sees everything.
- Docs to change once it ships: README "One proxy for every session", the site's sessions section (the line "a second session attaches and sees everything the first recorded"), and `docs/design.md`.

## Also open

- **Windows and Linux.** The proxy core is Node and mostly portable. Tied to macOS: the data folder from `HOME` (`hooks/register.tsx`), certificates through `openssl` (`sidecar/certs.mjs`), the system proxy through `networksetup` (`shared/systemproxy.mjs`, `sidecar/network.mjs`), Claude Code's own connections told apart with `ps`, `lsof` and `scutil` (`sidecar/selfguard.mjs`), CA trust through `security`, browser launch through `open`, and finding Node in Homebrew's places. Being tried on Windows first.
- **HTTP/3.** Keep clients on TCP (strip `h3` from `Alt-Svc`), show who talks QUIC past the proxy, and research full decryption.
