# Secret Broker

This is the credential vault boundary for the self-building assistant in the sibling
`assistant` repo. It exists so Claude can *use* secrets without ever holding them, and
so a sensitive request needs a human's phone approval instead of a blind file read.

Read `vault_plan.md` (design rationale) and `vault_implementation.md` (phased build
spec, exact API contract, and a "known weaknesses" section) in the `assistant` repo
before making a structural change here — this file is the day-to-day operating
contract, not the spec.

## The boundary this repo exists to enforce

- **This repo, and this service, must stay separate from the assistant** — separate
  git repo, separate OS user (`secret-broker`, never `claude-agent`), separate trust
  level. The assistant's own Claude session must never gain read access to this
  checkout, to `/etc/secret-broker/`, or to OpenBao's data. If a task ever asks you to
  blur that line — e.g. "just have the assistant read the broker's config" — stop and
  say why not, rather than finding a workaround.
- **The broker is deliberately small.** One Node process, one SQLite file, one JSON
  capability catalog, a handful of HTTP routes. Zero npm dependencies in the core
  service (`node:http`, `node:sqlite`, `node:crypto` only). If a change would add a
  framework, an ORM, a queue, or a second service, that's a sign to stop and reconsider,
  not to proceed. Every extra dependency is one more thing between an agent and the
  secrets this service guards.
- **`policies/capabilities.json` defines what the broker will let itself be asked for.**
  You may draft or propose an addition, but always show the user the exact diff and
  wait for their confirmation before treating it as final — this file is the whole
  access-control model, not ordinary application config.

## Never do these, even if asked to "just test it"

- Never print, log, commit, or paste an actual secret value, the OpenBao root token,
  the unseal key, an AppRole `role_id`/`secret_id`, a device bearer token, or the
  approver password's plaintext. Tests and fixtures use obviously-fake values
  (`test/dummy`, `not-a-real-secret`) — never a real path or a real credential.
- `bin/hash-password.mjs`, `bin/device.mjs`, and OpenBao admin operations (`bao
  operator init/unseal`, `bao-add-secret`, `bao login`) are written to be run
  **interactively by a human**, not invoked by an agent session and captured. Their
  whole purpose is keeping those values out of an LLM's context. If a task seems to
  require running one of them yourself, that's a sign the task should be handed back
  to the user as a short manual step instead.
- Don't relax `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, or the `secret-broker`/
  `openbao` OS user boundaries to make deployment more convenient.

## Development

- Node `>=22.13` (uses `node:sqlite`; run with `--disable-warning=ExperimentalWarning`
  to silence its warning, don't disable the feature itself).
- `npm test` runs `node --test` over `test/*.test.mjs`. Run it before every commit.
- No build step. `src/server.mjs` is the entry point.
- Commit after every tested change, one line saying what changed — same convention as
  the assistant repo.

## Deployment

- Laptop checkout: wherever you cloned it. VPS checkout: `/srv/secret-broker`, owned by
  the `secret-broker` OS user, cloned and pulled **as that user**
  (`sudo -u secret-broker git -C /srv/secret-broker pull --ff-only`), never as root —
  files written by root there can break the running service's file permissions.
- The VPS runs the broker with a dedicated Node install at
  `/opt/nodejs/current/bin/node`, not the box's system Node — check
  `/opt/nodejs/current/bin/node --version` is still `>=22.13` before assuming a plain
  `node` on `$PATH` will do.
- After pulling a change on the VPS: `systemctl restart secret-broker`, then confirm
  with `curl -s https://<broker-url>/health` (no auth needed) before considering the
  deploy done.
- Runtime config lives in `/etc/secret-broker/broker.env` on the VPS, outside this
  repo, and is never committed. `.gitignore` already excludes `broker.env`, `*.sqlite`,
  and logs — don't remove those entries.

## Reference

- `vault_plan.md`, `vault_implementation.md` — in the sibling `assistant` repo.
- `policies/capabilities.json` — the capability catalog.
- `tools/README.md` and `tools/_shared/secrets.mjs` in the `assistant` repo — the
  client side (`withCapability()`) that every assistant tool goes through.
