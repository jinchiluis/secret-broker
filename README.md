# Secret Broker

Small, dependency-free Node service that stands between the self-building
assistant (`claude-agent`) and an OpenBao vault. Claude requests named
capabilities; a human approves sensitive ones from their phone; the broker
is the only thing that ever talks to OpenBao.

This is a **separate repository and a separate OS user** from the assistant
on purpose — see the assistant repo's `CLAUDE.md` Security section. The
`claude-agent` user must never have read access to this repository or to
`/etc/secret-broker/` on the VPS.

## Build guide

Full spec, phased build steps, test checklist and known weaknesses live in
`vault_implementation.md` in the `assistant` repo (sibling directory on the
dev machine, `/srv/assistant` on the VPS). Read that before writing code
here. `vault_plan.md` in the same repo has the original design rationale.

## Layout (target — being filled in phase by phase)

```
src/            server.mjs, config.mjs, db.mjs, bao.mjs, capabilities.mjs,
                requests.mjs, approve.mjs, ntfy.mjs, audit.mjs, auth.mjs
bin/            hash-password.mjs, device.mjs
policies/       capabilities.json  (capability catalog, no secrets)
test/           node:test unit tests
```

## Deploy

Development happens both here (laptop) and on the VPS against the same
GitHub remote. On the VPS this repo is cloned to `/srv/secret-broker`,
owned by the `secret-broker` OS user — never by `claude-agent`. Runtime
config with real values (`BAO_ROLE_ID`, `BAO_SECRET_ID`, `NTFY_URL`,
`APPROVER_PASSWORD_HASH`, ...) lives in `/etc/secret-broker/broker.env`,
outside this repo, and is never committed.
