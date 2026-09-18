# Hardening backlog

Deferred by design — v1 is fully functional and in daily use without any of these.
See `CLAUDE.md` for the operating rules and `../assistant/vault_plan.md` for the
original design rationale. None of this is urgent; pick items up as they become
worth the added complexity.

- [ ] **Fill helper on the VPS** — a new route, `POST /v1/requests/:id/fill`, taking
  `{ cdp_port, url_prefix, steps: [{ selector, field }, { click: selector }] }`. The
  broker connects to `http://127.0.0.1:<cdp_port>` with Playwright's
  `chromium.connectOverCDP`, checks the page URL starts with `url_prefix`, types the
  fields itself, disconnects. `collect` is then disabled for `use`-mode capabilities
  on devices flagged `local=true` (only the VPS device gets that flag). This is the
  point where the requesting process never holds a credential in memory — currently
  it does, for the duration of its use. Only meaningful on the VPS: on the laptop,
  the tool process and the operator are the same OS user regardless. Turns the
  broker into a Playwright-dependent service (currently zero npm dependencies).
- [ ] **WebAuthn/passkey** for approver login (`@simplewebauthn/server`), replacing
  the password for `highly_sensitive` capabilities (the Visa card, passport data).
  Closes the single-factor-approval gap.
- [ ] **Timed approvals** — "approve for 10 minutes" instead of one-shot: the broker
  auto-approves repeat requests for the same capability+device until a stored
  `until` timestamp, still audited.
- [ ] **Tailscale ACL tagging** (`tag:server` on the VPS) so only the owner's own
  devices can reach the broker's `:8443`, not just "anyone on this tailnet."
- [ ] **Rate-limit alerts** — a second ntfy ping if 5+ requests arrive in 10
  minutes, or 3 denials happen in a row (could mean a compromised/misbehaving tool).

## Known limitations (why these are lower priority than they might look)

- The AppRole `role_id`/`secret_id` sit on the VPS disk, readable by root (POSIX
  permissions don't apply to root). The broker host is the vault's real trust
  boundary — not fixable without heavier infrastructure (HSM, remote auto-unseal)
  than a personal VPS needs, and out of scope here.
- A capability approval is coarse: approving a login approves the whole session, not
  "read only, this once." Operation-level safety stays with each tool's own
  confirmation step (e.g. the Postbank transfer tool's BestSign comparison), not
  something the broker itself can enforce.
- ntfy.sh sees capability names, device names, and self-reported reasons for every
  request — never a secret value.
