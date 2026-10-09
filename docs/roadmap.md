# Wirepane roadmap

What comes next, in order. Each item says what changes for the person using it, then how it could be built.

## Next: one proxy, a request list per session

**Today.** Every Claude Code session on the Mac shares one proxy and one list. A second session attaches and sees everything the first recorded: its requests, its tracked domains, the hosts that passed through. Clear in one session clears the list for all of them.

**Next.** The proxy stays one: one port, one CA, one process, one capture on disk. Each session gets its own list.

- **What a session sees.** By default, the requests that arrived after it attached and that match its own scope. A **Show all sessions** switch in the pane (and `scope: "all"` in the tools) shows the whole capture.
- **Tracked domains, per session.** Each session has its own set, and it works for that session alone. Today the set is one global list in `~/.claude/proxy-mod/tracking.json`, and `track_domains` in one session changes it for all.
  - The proxy decrypts and records a host when at least one attached session tracks it, or when some session tracks nothing (it wants everything). The rest pass through untouched, as today.
  - A session's list holds the hosts of its own set. A session that tracks nothing sees everything.
  - "Passed through" (the hosts offered for tracking in the Domains view and in the doctor) is per session too: the hosts this session's set left out.
  - `track_domains`, the Domains view and the doctor's tracking findings act on this session's set.
  - **The set is remembered by the project folder.** Open Claude Code in the same folder tomorrow and its domains are there; `/clear` and a restart keep them; two sessions in one folder share the set. This is also what fixes the old bug: tracking was keyed by the session id, `/clear` changed the id, and the domain filter stopped working.
  - It is kept in `~/.claude/proxy-mod/projects/<the folder's hash>/tracking.json`, with the folder's path inside, so nothing is added to the project's repository.
  - The global list of today seeds, once, each project that has no set of its own yet, so nothing tracked is lost; after that the sets go their own ways.
- **More of the scope**, to settle in the design:
  - the clients a session claims, such as "this session is the iOS Simulator, that one is the Android emulator";
  - its project's rules: requests its rules changed always belong to it.
- **Claude's tools.** `list_requests`, `search_requests`, `wait_for_request`, `diff_requests` and `export_har` work on the session's own list. `get_request` and `replay_request` still reach any id, so a request one session points to can be opened from another.
- **Clear** clears this session's list only. The capture on disk is kept for the others and goes as it does today (two days after its last use).
- **Health** lists each attached session with its scope and how many requests it holds.

**How.**

- The sidecar tags each flow, as it is recorded, with the sessions whose scope it matches. The `flow` event carries the tags, and the backlog a session gets on attach is filtered by them.
- A session's scope must survive `/clear`: the session id changes then, and `$.state` resets. It has to be keyed by something that stays, such as the project folder, or carried over by `reattach`, which already follows the id change.
- The tests: a set is back after the session ends and a new one opens in the same folder; two attached sessions in different folders, with different tracked domains, each record and list their own hosts, and a host neither tracks passes through; a session that tracks nothing sees everything; `track_domains` in one leaves the other's set alone; `/clear` keeps the set; Clear in one leaves the other's list whole; Show all sees everything.
- Docs to change once it ships: README "One proxy for every session", the site's sessions section (the line "a second session attaches and sees everything the first recorded"), and `docs/design.md`.

## Also open

- **Windows and Linux.** The proxy core is Node and mostly portable. Tied to macOS: the data folder from `HOME` (`hooks/register.tsx`), certificates through `openssl` (`sidecar/certs.mjs`), the system proxy through `networksetup` (`shared/systemproxy.mjs`, `sidecar/network.mjs`), Claude Code's own connections told apart with `ps`, `lsof` and `scutil` (`sidecar/selfguard.mjs`), CA trust through `security`, browser launch through `open`, and finding Node in Homebrew's places. Being tried on Windows first.
- **HTTP/3.** Keep clients on TCP (strip `h3` from `Alt-Svc`), show who talks QUIC past the proxy, and research full decryption.
