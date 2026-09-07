# Vaultwarden secret source for Hermes

A small, **read-only** Hermes plugin that loads credentials from a self-hosted
Vaultwarden vault through the official Bitwarden Password Manager CLI (`bw`).
It does not use the `bws` CLI for Bitwarden Secrets Manager.

## Security model

- The plugin reads an ordered `item_ids` list of immutable Vaultwarden UUIDs,
  never mutable item names.
- It consumes only hidden custom fields whose names are valid environment
  variable names. Values are never printed.
- Each item is atomic: if a valid field conflicts with one loaded from an
  earlier item, the entire later item is skipped.
- Every source load runs one fresh `bw sync`, then reads the configured items
  in order. This observes credential rotations without copying values into
  `.env`.
- Bootstrap state and the generated Bitwarden session remain in a mode-`0700`,
  task-local directory under `/tmp`; the session file is mode `0600`. Neither
  is written to the persistent Hermes volume, configuration, repository, or
  logs.
- A file lock serializes concurrent Hermes processes in the same task. One
  process bootstraps or replaces an expired session; the others wait for it.
- Failures are fail-open for Hermes startup and produce only safe,
  non-interactive diagnostics.

### Scope the Vaultwarden account

The configured UUIDs determine which secrets Hermes loads, but they do **not**
limit what the bootstrap account can decrypt. Any process that can read the
three bootstrap credentials can authenticate as that account and read every
item available to it.

Create a dedicated non-human Vaultwarden account for Hermes. Keep its personal
vault empty and grant it access only to the shared collection(s) containing the
required secrets. Do not use a personal, administrator, or broadly shared
account. Use a separate API key and master password for this account; mount
those values only into the Hermes task. When retiring the deployment, revoke
collection access and rotate or revoke the bootstrap credentials.

## Configuration

The source is opt-in. Configure it under `secrets.vaultwarden` in the Hermes
configuration. A working configuration requires every parameter below.

| Parameter | Requirement | Purpose |
| --- | --- | --- |
| `enabled` | `true` | Enables this secret source. |
| `server_url` | An `https://` URL | Self-hosted Vaultwarden endpoint. |
| `client_id` | Non-empty value | Bitwarden API client ID for the dedicated account. |
| `client_secret` | Non-empty value | Bitwarden API client secret for the dedicated account. |
| `master_password` | Non-empty value | Master password for the dedicated account. |
| `item_ids` | Non-empty list of unique UUIDs | Vaultwarden items to load, in order. |

Each bootstrap credential can independently be configured in either form:

- **Docker secret file**: an absolute path prefixed with `file://`, such as
  `file:///run/secrets/hermes-vaultwarden-client-id`. The secret value is not
  stored in the Hermes configuration.
- **Literal value**: a value used as-is. Prefer a Hermes `${VAR}` or
  `${env:VAR}` reference, expanded from `~/.hermes/.env` before this plugin
  runs. A bare literal is appropriate only when deployment tooling renders the
  configuration and keeps it out of version control.

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
```

`${HERMES_VW_MASTER_PASSWORD}` is expanded by Hermes from a matching entry in
`~/.hermes/.env`; the curly braces are required. A bare `$VAR` is not expanded
and is passed to the plugin as a literal string.

The credential forms can be mixed. `item_ids` is required even when Hermes
needs credentials from a single Vaultwarden item. Every entry must be a unique
UUID.

### Optional parameters

| Parameter | Default | Use it when |
| --- | --- | --- |
| `binary` | `$HERMES_HOME/bin/bw`, then `PATH` | The trusted `bw` executable is elsewhere. The configured path must be absolute and executable. |
| `runtime_dir` | `/tmp/hermes-vaultwarden` | The task needs a different absolute, writable, task-local ephemeral directory. Do not use a persistent or shared volume. |
| `timeout_seconds` | `90` | The full fetch needs a different positive timeout. |
| `override_existing` | `true` | Existing non-protected environment values should win; set it to `false`. |
| `session_env` | `BW_SESSION` | The reserved session environment variable has a non-default name. It is protected and is never loaded from Vaultwarden. |

The plugin never downloads `bw`. Install the official CLI before enabling the
source.

## Vault setup and runtime behavior

1. Create one or more Vaultwarden items, grouped by category or stack.
2. Add provider credentials as **hidden custom fields**. Field names must be
   the intended environment variable names, such as `OPENAI_API_KEY` and
   `ANTHROPIC_API_KEY`.
3. Ensure a field name appears in only one configured item. A collision skips
   the complete later item rather than partially applying it.
4. Deploy or restart Hermes. On the first task start, and after each
   reschedule, a lock holder bootstraps the local CLI state with the equivalent
   of:

   ```bash
   bw config server 'https://vaultwarden.example.com'
   bw config server # verify the HTTPS URL persisted in task-local CLI state
   bw status --raw
   # if unauthenticated:
   bw login --apikey
   # if locked:
   bw unlock --passwordenv BW_PASSWORD --raw
   bw sync
   bw get item '<each-configured-vault-item-uuid>'
   ```

`BW_SESSION` is neither an input nor persistent configuration. The generated
session is shared only inside the current task-local runtime directory and is
recreated after a reschedule.

## Installation and validation

Enable the Git-installed plugin after reviewing it:

```bash
hermes plugins enable vaultwarden-secret-source
```

Then verify only safe state:

1. `hermes plugins list --plain --no-bundled` lists
   `vaultwarden-secret-source` as enabled.
2. `hermes status --all` reports the expected providers as configured.
3. Run bounded provider smokes without printing credentials or response
   content.
4. Restart or reschedule one controlled task and repeat the checks. Passing
   both attempts confirms the task can bootstrap independently of prior state.

## Local validation

Dependencies are managed with [uv](https://docs.astral.sh/uv/). `uv run`
creates `.venv/` and installs the `dev` dependency group from `pyproject.toml`
and `uv.lock`.

Run the hermetic test suite against a compatible Hermes source checkout. The
conformance test imports Hermes' own test helpers, so an installed runtime
alone is not enough:

```bash
PYTHONPATH=/path/to/hermes-agent \
  PYTHONDONTWRITEBYTECODE=1 \
  uv run --group dev pytest tests/
```

## License

[MIT](LICENSE)
