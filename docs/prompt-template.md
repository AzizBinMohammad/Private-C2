# Prompt Template for Feature Requests

A starting point for asking an AI assistant (or another engineer) to add a
feature to Private-C2. The template exists because of a specific hazard in this
repository: **a large fraction of the code is well-written, compiles, and is
never executed by anything.**

An instruction that does not say where the feature should live can produce a
correct-looking implementation in a package no binary imports.

---

## Template

```
Add <feature> to Private-C2.

Scope:
- Surfaces: <CLI / web portal / MCP / server API only>  (pick which)
- Live execution path: yes — it must actually run in
  cmd/server, cmd/client, cmd/implant or server/c2. If it
  belongs in implant/ or client/ library packages, say so
  explicitly, otherwise treat those as dead code.

Requirements:
- <what it does, inputs, outputs, edge cases>
- <what it must NOT do>

Constraints:
- Reuse existing helpers (pkg/, server/core/, implant/safety/)
  before writing new ones.
- No new dependencies.
- Don't touch files outside the above scope.
- If this needs an architectural change, tell me first
  instead of deciding.

Verify before you're done:
- make test passes (all 9 modules)
- If user-facing, show me how to exercise it end to end
- Say plainly what you verified vs. what you only reasoned about
```

For a small change, skip the template and say what you want plus "in the live
path". That is usually enough.

---

## Worked example

The largest real gap in the project — the OT/ICS module has no way to run:

```
Add OT/ICS task types to the implant so an assessment can
actually run.

Scope:
- Surfaces: server API + implant (CLI/portal dispatch can follow)
- Live path: yes. implant/modules/ot/** is currently imported
  by nothing and cmd/implant implements only 9 task types,
  none OT. Wire it into the live dispatch, don't add more
  library code.

Requirements:
- Add OT task types to cmd/implant's handleTask, routed into
  implant/modules/ot.
- Add an endpoint that queues an assessment for a session.
- Keep the existing read-only posture and pre-flight checks.

Constraints:
- No new dependencies. Reuse implant/safety for the checks.
- Don't touch the web portal in this change.

Verify:
- make test, plus a live run showing an OT task dispatched to
  a real implant and a finding stored and read back.
```

---

## The lines that carry the most weight

| Line | Why it matters |
|---|---|
| **"Live execution path: yes"** | Without it, a feature can land entirely in code nothing calls. `implant/modules/ot/**` (32 files, 17 protocol clients), `client/cli/commands/**`, `server/build/**`, `server/core/**` and `server/api/grpc/**` all compile and are all unreachable. |
| **"Surfaces: pick one"** | The CLI and the web portal are two independent implementations of the same features, and the CLI's `client/cli/commands` tree is dead code that looks alive. Naming the surface stops the work landing in the wrong one. |
| **"If this needs an architectural change, tell me first"** | `CLAUDE.md` rule 1 says plan and wait for approval; the long-form brief says keep going. State which you want, per request. |
| **"Say what you verified vs. reasoned about"** | Every phase doc is stamped `DONE`, and Phase 6 is contradicted by its own source. Unverified completion claims are a real hazard here. |

---

## Project facts worth stating in a prompt

- **Don't trust the phase documents.** All eight claim `DONE`. Treat them as
  intent, not status; `docs/known-issues.md` and
  `docs/audit-2026-10-15.md` are the accurate picture.
- **Configuration is flags, not environment.** `server/config` reads `PC2_*`
  variables but is imported by nothing; `cmd/server` uses the `flag` package.
  Say which mechanism a config-driven feature should use.
- **Sessions, task queues, results and listeners are in-memory only**
  (`server/c2/`). They do not survive a restart and are not database rows.
  Anything that needs to act on a live session goes through `ImplantServer`.
- **Two ways to talk to a session exist and disagree.** The live path is a raw
  TLS socket carrying JSON register/checkin/result messages. The
  `server/c2/listener/*` implementations use client-certificate CN as the
  session ID with a request/response handler and cannot be substituted without
  changing the implant's wire protocol.
- **Only `mtls` listeners are implemented.** Other transport types are refused
  with a 400 rather than silently stored.
- **Payload generation shells out to `go build`** and needs the source tree and
  a Go toolchain on the host — which is why it cannot work in the Docker image.
- **`make test` covers all 9 modules** and runs with `-race`. `make lint` runs
  `go vet` (plus `golangci-lint` if installed); `gofmt` is *not* enforced —
  56 files currently fail it (`gofmt -l ./pkg ./server ./client ./implant ./cmd`).
  Reformatting them is a separate, deliberate commit; don't let it bloat a
  feature diff.

---

## Adding a feature that spans CLI and portal

When a capability should be reachable from both, say so explicitly and ask for
the shared logic to sit in one place:

```
Add <feature> to both the CLI and the web portal.

- Both must use the same server endpoint and the same
  business logic; don't implement it twice.
- Probe the endpoint via curl and show the exact response
  shape before wiring either client to it.
- The portal injects server data into HTML: use esc() for text
  and attributes, and jsArg() for values inside inline
  onclick="fn('...')" handlers. Never interpolate a raw value.
```

The CLI already goes through `client/api` for authenticated requests — reuse it
rather than adding another HTTP client. `cmd/mcp` still has its own equivalent
(`c2Client`); consolidating it is tracked in `docs/audit-2026-10-15.md`.
