# OpenBao capability playbook

Use this playbook when adding or rotating a secret that the assistant may use through the Secret Broker. Never put secret values in Git, chat, command arguments, logs, or shell history.

## Trust boundary

- OpenBao is reachable only by the Secret Broker.
- The assistant requests named capabilities; it never reads OpenBao directly.
- `policies/capabilities.json` is the access-control catalog and contains no secret values.
- Run OpenBao administration and `bao-add-secret` yourself in an interactive SSH terminal. Do not ask an agent to run or capture them.

## Add a capability

1. Choose a narrow capability name, one OpenBao path, the minimum required fields, and an appropriate sensitivity level.
2. Add the proposed entry to `policies/capabilities.json` only after showing the exact diff to the user and receiving confirmation.
3. Validate and deploy:

   ```bash
   cd /srv/secret-broker
   sudo -H -u secret-broker /opt/nodejs/current/bin/node --test test/*.test.mjs
   sudo -H -u secret-broker git -C /srv/secret-broker pull --ff-only
   systemctl restart secret-broker
   systemctl is-active secret-broker
   ```

4. Confirm the public `/health` endpoint returns HTTP 200.

## Enroll or rotate secret fields

Connect from your own terminal:

```bash
ssh root@<vps-host>
```

Run the human-only helper with the catalog's `secret` path followed by its field names:

```bash
bao-add-secret <path> <field> [<field>...]
```

The helper prompts silently for the OpenBao root token and every field. Re-running it for the same path replaces the stored values, so the same command is used for rotation.

Amazon Visa example:

```bash
bao-add-secret bank/amazon-visa email access_code
```

Enter these only at the hidden prompts:

1. OpenBao root token
2. Amazon Visa login email
3. Four-digit Amazon Visa Zugangscode

SMS one-time codes are never stored. If the provider requests one, the automation must pause for the user.

## Verify use

Run the corresponding assistant tool. A sensitive capability should create a phone approval request. After approval, the broker releases only the catalogued fields once to the requesting device. The tool must consume them transiently and never print or persist them.

## Remove access

Removing a capability and deleting its OpenBao secret are separate operations:

1. Remove the entry from `policies/capabilities.json` after showing the exact diff and receiving confirmation.
2. Test, deploy, and restart the broker.
3. Have a human remove the OpenBao value through an interactive administrator session. Never place the root token or secret value on a command line.

