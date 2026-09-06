# Vaultwarden secret source for Hermes

A small, **read-only** Hermes plugin that loads credentials from a Vaultwarden
vault through the official Bitwarden Password Manager CLI (`bw`). It does not
use the `bws` CLI for Bitwarden Secrets Manager.

## Security model

- The plugin reads an ordered `item_ids` list, always by immutable **UUID**
  rather than mutable names.
- Only hidden custom fields with valid environment-variable names are consumed;
  values are never printed. Items are applied atomically: if one item's valid
  field conflicts with an earlier item, the whole later item is skipped.
- One fresh `bw sync` runs before every configured item is read, so credential
  rotations are observed without copying values into `.env`.
- A Docker task bootstraps `bw` from the configured credentials (Docker
  secrets and/or literal config values) before its first Vaultwarden
  operation. It verifies the configured HTTPS server persisted in the same
  task-local CLI state, then reads `bw status --raw`: it logs in only when
  unauthenticated and unlocks only when locked. A file lock serializes
  concurrent Hermes processes, so they share one bootstrap rather than each
  creating a login.
- The generated session and Bitwarden CLI state live only in a mode-`0700`
  task-local directory under `/tmp`; the session file is mode `0600`. They are
  never written to the persistent Hermes volume, configuration, repository, or
  logs.
- An expired session is invalidated and re-established by the lock holder only;
  other gateway processes wait for that replacement rather than logging in too.
- Source failures are fail-open for Hermes startup and emit only safe
  diagnostics. They never prompt on a non-interactive gateway or cron path.

### Scope the Vaultwarden account

The configured item UUIDs select what Hermes loads, but they do **not** limit
what the bootstrap credentials can decrypt. A process that can read the three
bootstrap values (whichever Docker secret files or rendered config they
resolve to) can authenticate as that Vaultwarden account and read every item
the account can access.

Create a dedicated non-human Vaultwarden account for Hermes. Its personal vault
should be empty, and it should be granted access only to the shared
collection(s) containing the secrets Hermes needs. Do not use a personal,
administrator, or broadly shared account. Create a separate API key and master
password for that account, mount them only into the Hermes task, and revoke its
collection access and rotate or revoke its bootstrap credentials when retiring
the deployment.

## Configuration

The source is opt-in. Configure the Vaultwarden URL and the three bootstrap
credentials (`client_id`, `client_secret`, `master_password`); their values
must never be placed in this repository or in chat.

Each of the three credentials is configured independently as either:

- **a Docker secret file** — an absolute path prefixed with `file://`, e.g.
  `file:///run/secrets/hermes-vaultwarden-client-id`. The value never appears
  in the config file itself; or
- **the literal value** — used as-is. Write it as a Hermes `${VAR}` /
  `${env:VAR}` reference (expanded from `~/.hermes/.env` when `config.yaml`
  loads, before this plugin ever sees the value) so the config file committed
  to this repository never contains the secret itself. A bare, unexpanded
  literal is only safe in a config rendered at deploy time by your own
  tooling and kept out of version control.

```yaml
secrets:
  vaultwarden:
    enabled: true
    server_url: "https://vaultwarden.example.com"
    client_id: file:///run/secrets/hermes-vaultwarden-client-id
    client_secret: file:///run/secrets/hermes-vaultwarden-client-secret
    master_password: ${HERMES_VW_MASTER_PASSWORD}
    item_ids:
      - "<vault-item-uuid-models>"
      - "<vault-item-uuid-integrations>"
    override_existing: true
```

`${HERMES_VW_MASTER_PASSWORD}` above is resolved by Hermes itself (not by
this plugin) from a matching `HERMES_VW_MASTER_PASSWORD=...` line in
`~/.hermes/.env`; note the required curly braces — a bare `$VAR` is not
expanded and would be passed through as a literal, useless string.

The two modes can be mixed freely across the three credentials. `item_ids` is
required even when Hermes needs only one vault item. Every UUID in the list
must be unique.

Docker secret files are mounted read-only with restrictive permissions and
read directly. The default runtime directory is `/tmp/hermes-vaultwarden`; it
can be changed with `runtime_dir` when the alternative is an absolute,
task-local writable path.

## Vault setup

1. Create one or more Vaultwarden items, grouped by category or stack.
2. Add provider credentials as **hidden custom fields**. Field names must match
   the intended environment variables, for example `OPENAI_API_KEY` and
   `ANTHROPIC_API_KEY`. A field name may appear in only one configured item:
   a collision skips the entire later item rather than partially applying it.
3. Deploy or restart Hermes. On the first task start, and after every
   reschedule, one lock holder runs the equivalent of:

   ```bash
   bw config server 'https://vaultwarden.example.com'
   bw config server # verify the same CLI state retained the HTTPS URL
   bw status --raw
   # if unauthenticated:
   bw login --apikey
   # if locked:
   bw unlock --passwordenv BW_PASSWORD --raw
   bw sync
   bw get item '<each-vault-item-uuid>'
   ```

`BW_SESSION` is intentionally not used as an input or persisted in `.env`. The
generated session is shared only inside the current container's ephemeral
runtime directory and is recreated after a reschedule.

## Installation and validation

For a Git-installed plugin, enable it explicitly after review:

```bash
hermes plugins enable vaultwarden-secret-source
```

Then verify only safe state:

1. `hermes plugins list --plain --no-bundled` lists
   `vaultwarden-secret-source` as enabled.
2. `hermes status --all` reports the expected providers as configured.
3. Run bounded provider smokes without printing response content or
   credentials.
4. Restart or reschedule one controlled task and repeat the checks. Passing
   both attempts proves the task can bootstrap independently of prior state.

## Local validation

Dependencies are managed with [uv](https://docs.astral.sh/uv/); `uv sync` (run
automatically by `uv run`) creates `.venv/` and installs the `dev` dependency
group from `pyproject.toml`/`uv.lock`.

Run the hermetic test suite, including the official secret-source conformance
kit (`tests/test_conformance.py`), against a compatible Hermes source/runtime:

```bash
PYTHONPATH=/path/to/hermes-agent \
  PYTHONDONTWRITEBYTECODE=1 \
  uv run --group dev pytest tests/
```

## License

[MIT](LICENSE)
