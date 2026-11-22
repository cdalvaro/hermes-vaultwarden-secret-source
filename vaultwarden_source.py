"""Vaultwarden provider for Hermes' pluggable SecretSource interface.

The source uses a container-local runtime directory to share one Bitwarden CLI
login among Hermes processes in the same task. The directory is created below
the system temporary directory with restrictive permissions, never in the
shared Hermes volume, and is discarded when the container is replaced or rescheduled.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Optional

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    classify_cli_error,
    get_source_environment,
    is_valid_env_name,
    run_secret_cli,
)

try:
    # Hermes loads __init__.py as a package (submodule_search_locations=[plugin_dir]),
    # which makes this a proper submodule and resolves these relatively.
    from ._config import (
        DEFAULT_SESSION_ENV,
    )
    from ._config import (
        item_ids as _item_ids,
    )
    from ._config import (
        session_env as _session_env,
    )
    from ._runtime import (
        acquire_runtime_lock as _acquire_runtime_lock,
    )
    from ._runtime import (
        bw_state_dir as _bw_state_dir,
    )
    from ._runtime import (
        invalidate_runtime_bootstrap as _invalidate_runtime_bootstrap,
    )
    from ._runtime import (
        prepare_runtime_dir as _prepare_runtime_dir,
    )
    from ._runtime import (
        read_runtime_session as _read_runtime_session,
    )
    from ._runtime import (
        release_runtime_lock as _release_runtime_lock,
    )
    from ._runtime import (
        remaining_seconds as _remaining_seconds,
    )
    from ._runtime import (
        write_runtime_session as _write_runtime_session,
    )
except ImportError:
    # Imported flat (e.g. tests put the plugin dir on sys.path directly and
    # import this file on its own, with no parent package).
    from _config import (
        DEFAULT_SESSION_ENV,
    )
    from _config import (
        item_ids as _item_ids,
    )
    from _config import (
        session_env as _session_env,
    )
    from _runtime import (
        acquire_runtime_lock as _acquire_runtime_lock,
    )
    from _runtime import (
        bw_state_dir as _bw_state_dir,
    )
    from _runtime import (
        invalidate_runtime_bootstrap as _invalidate_runtime_bootstrap,
    )
    from _runtime import (
        prepare_runtime_dir as _prepare_runtime_dir,
    )
    from _runtime import (
        read_runtime_session as _read_runtime_session,
    )
    from _runtime import (
        release_runtime_lock as _release_runtime_lock,
    )
    from _runtime import (
        remaining_seconds as _remaining_seconds,
    )
    from _runtime import (
        write_runtime_session as _write_runtime_session,
    )

_DEFAULT_TIMEOUT_SECONDS = 90.0
# A few spaced attempts ride out a Vaultwarden restart; all of them share the
# single fetch deadline, so a real outage still ends within timeout_seconds.
_MAX_ATTEMPTS = 3
_RETRY_DELAY_SECONDS = 5.0
# Every bootstrap step reports its own classified error, so AUTH_FAILED really
# means rejected credentials (a restarting server surfaces as NETWORK or
# INTERNAL) and retrying it would only repeat the rejected login.
_PERMANENT_ERRORS = frozenset(
    {
        ErrorKind.NOT_CONFIGURED,
        ErrorKind.BINARY_MISSING,
        ErrorKind.REF_INVALID,
        ErrorKind.AUTH_FAILED,
    }
)
_DEFAULT_RUNTIME_DIR = Path(tempfile.gettempdir()) / "hermes-vaultwarden"
_BOOTSTRAP_ENV_NAMES = frozenset({"BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"})
_HIDDEN_FIELD_TYPE = 1  # bw's `fields[].type`: 0 text, 1 hidden, 2 boolean, 3 linked
_FILE_SCHEME_PREFIX = "file://"
_ENV_SCHEME_PREFIX = "env:"
_BOOTSTRAP_KEYS = ("client_id", "client_secret", "master_password")
# bw is a Node program: it trusts a private CA only through NODE_EXTRA_CA_CERTS
# (it ignores SSL_CERT_FILE) and reads lowercase proxy variables.
_BW_PASSTHROUGH_ENV = (
    "NODE_EXTRA_CA_CERTS",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
)
_BOOTSTRAP_VALUE_DESCRIPTION = (
    "a `file:///absolute/path` secret file, `env:NAME`, or the literal value"
)

_SETUP_HINT = (
    "Check client_id, client_secret, master_password (each a file:///absolute/path, "
    "env:NAME or the literal value) and server_url under secrets.vaultwarden "
    "in your Hermes config; see this plugin's README for the expected layout."
)
_REMEDIATION_HINTS = {
    ErrorKind.NOT_CONFIGURED: _SETUP_HINT,
    ErrorKind.BINARY_MISSING: "Install the official `bw` CLI and point secrets.vaultwarden.binary at it, or ensure it is on PATH.",
    ErrorKind.AUTH_FAILED: f"Vaultwarden rejected the bootstrap credentials or server URL. {_SETUP_HINT}",
    ErrorKind.AUTH_EXPIRED: "The shared bw session expired and could not be replaced; check Vaultwarden connectivity and retry.",
}


class VaultwardenSource(SecretSource):
    """Read configured Vaultwarden items through the trusted ``bw`` CLI."""

    name = "vaultwarden"
    label = "Vaultwarden"
    shape = "bulk"
    scheme = "bw"

    def __init__(self) -> None:
        self._bootstrap_session: Optional[str] = None
        self._bootstrap_env: dict[str, str] = {}

    def override_existing(self, cfg: dict) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("override_existing", True))

    def protected_env_vars(self, cfg: dict):
        """Never let vault fields replace session or bootstrap credentials,
        the variables that ``env:NAME`` bootstrap values read, or the CA and
        proxy settings that decide how bw reaches the vault."""
        return frozenset(
            {
                _session_env(cfg),
                *_BOOTSTRAP_ENV_NAMES,
                *_BW_PASSTHROUGH_ENV,
                *_bootstrap_env_refs(cfg),
            }
        )

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        try:
            timeout = float(
                (cfg or {}).get("timeout_seconds", _DEFAULT_TIMEOUT_SECONDS)
            )
        except (TypeError, ValueError):
            return _DEFAULT_TIMEOUT_SECONDS
        return timeout if timeout > 0 else _DEFAULT_TIMEOUT_SECONDS

    def remediation(self, kind: Optional[ErrorKind], cfg: dict) -> str:
        return _REMEDIATION_HINTS.get(kind, "") if kind is not None else ""

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "item_ids": {
                "description": "Ordered UUIDs of Vaultwarden items whose custom fields hold secrets",
            },
            "session_env": {
                "description": "Legacy: an extra variable name protected from Vaultwarden; bw always receives BW_SESSION",
                "default": DEFAULT_SESSION_ENV,
            },
            "binary": {
                "description": "Optional absolute path to the trusted bw CLI binary",
                "default": "",
            },
            "server_url": {
                "description": "Vaultwarden HTTPS URL used for non-interactive bootstrap",
                "default": "",
            },
            "client_id": {
                "description": f"Bitwarden API client ID: {_BOOTSTRAP_VALUE_DESCRIPTION}",
                "default": "",
            },
            "client_secret": {
                "description": f"Bitwarden API client secret: {_BOOTSTRAP_VALUE_DESCRIPTION}",
                "default": "",
            },
            "master_password": {
                "description": f"Vaultwarden master password: {_BOOTSTRAP_VALUE_DESCRIPTION}",
                "default": "",
            },
            "runtime_dir": {
                "description": "Absolute ephemeral directory shared by processes in one container task",
                "default": str(_DEFAULT_RUNTIME_DIR),
            },
            "override_existing": {
                "description": "Vault values overwrite .env/shell values, never the session token",
                "default": True,
            },
            "timeout_seconds": {
                "description": "Total deadline for the complete Vaultwarden fetch",
                "default": _DEFAULT_TIMEOUT_SECONDS,
            },
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        """Fetch with a short retry: Hermes reads the vault when a process
        starts (and only on some later re-reads, such as cron runs), so a
        Vaultwarden that is still restarting would otherwise leave the process
        without secrets until the next read."""
        cfg = cfg if isinstance(cfg, dict) else {}
        deadline = time.monotonic() + self.fetch_timeout_seconds(cfg)
        attempt = 1
        while True:
            result = self._fetch_once(cfg, home_path, deadline)
            if not _is_transient(result) or attempt >= _MAX_ATTEMPTS:
                break
            remaining = _remaining_seconds(deadline)
            if remaining is None or remaining <= _RETRY_DELAY_SECONDS:
                break
            time.sleep(_RETRY_DELAY_SECONDS)
            attempt += 1
        if attempt > 1 and result.secrets:
            result.warnings.append(f"Vaultwarden fetch succeeded on attempt {attempt}")
        return result

    def _fetch_once(self, cfg: dict, home_path: Path, deadline: float) -> FetchResult:
        result = FetchResult()
        session_env = _session_env(cfg)
        if not is_valid_env_name(session_env):
            result.error = "secrets.vaultwarden.session_env is not a valid environment variable name"
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        placeholder = _unexpanded_placeholder(cfg)
        if placeholder:
            result.error = (
                f"secrets.vaultwarden.{placeholder} looks like an unexpanded ${{...}} "
                "placeholder; Hermes does not expand the secrets: section. "
                "Use env:NAME or file:///path instead."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        item_ids = _item_ids(cfg)
        if item_ids is None:
            result.error = "Configure secrets.vaultwarden.item_ids as unique Vaultwarden item UUIDs"
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        binary = find_bw(home_path, str(cfg.get("binary") or "").strip())
        result.binary_path = binary
        if binary is None:
            result.error = "bw CLI was not found; configure secrets.vaultwarden.binary"
            result.error_kind = ErrorKind.BINARY_MISSING
            return result

        runtime_dir = _runtime_dir(cfg)
        if runtime_dir is None or not _prepare_runtime_dir(runtime_dir):
            result.error = (
                "secrets.vaultwarden.runtime_dir must be a writable absolute directory"
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        lock_fd = _acquire_runtime_lock(runtime_dir, deadline)
        if lock_fd is None:
            result.error = "Vaultwarden bootstrap lock timed out"
            result.error_kind = ErrorKind.TIMEOUT
            return result
        try:
            bootstrapped = self._bootstrap_if_needed(binary, cfg, runtime_dir, deadline)
            if isinstance(bootstrapped, ErrorKind):
                result.error = "Vaultwarden bootstrap authentication is unavailable"
                result.error_kind = bootstrapped
                return result
            session, session_extra_env = bootstrapped

            synced = _run_bw(binary, ["sync"], session, session_extra_env, deadline)
            if synced is None or synced.returncode != 0:
                error_kind = _error_kind(synced, deadline)
                if error_kind not in (ErrorKind.AUTH_EXPIRED, ErrorKind.AUTH_FAILED):
                    result.error = (
                        "bw could not synchronize the configured Vaultwarden vault"
                    )
                    result.error_kind = error_kind
                    return result
                self._clear_bootstrap()
                # Under the lock: if another process already replaced the shared
                # session, adopt it; only a still-current stale one is discarded.
                if _read_runtime_session(runtime_dir) == session:
                    _invalidate_runtime_bootstrap(runtime_dir)
                bootstrapped = self._bootstrap_if_needed(
                    binary, cfg, runtime_dir, deadline
                )
                if isinstance(bootstrapped, ErrorKind):
                    result.error = "Vaultwarden bootstrap authentication is unavailable"
                    result.error_kind = bootstrapped
                    return result
                session, session_extra_env = bootstrapped
                synced = _run_bw(binary, ["sync"], session, session_extra_env, deadline)
                if synced is None or synced.returncode != 0:
                    result.error = (
                        "bw could not synchronize the configured Vaultwarden vault"
                    )
                    result.error_kind = _error_kind(synced, deadline)
                    return result

            for item_id in item_ids:
                completed = _run_bw(
                    binary, ["get", "item", item_id], session, session_extra_env, deadline
                )
                if completed is None or completed.returncode != 0:
                    result.warnings.append(
                        "Skipped a Vaultwarden item that could not be read"
                    )
                    continue
                try:
                    item = json.loads(completed.stdout)
                except (TypeError, json.JSONDecodeError):
                    result.warnings.append(
                        "Skipped a Vaultwarden item with invalid JSON"
                    )
                    continue
                if not isinstance(item, dict):
                    result.warnings.append(
                        "Skipped a Vaultwarden item with an unexpected response"
                    )
                    continue

                fields = item.get("fields")
                if not isinstance(fields, list):
                    result.warnings.append("Vaultwarden item has no custom-fields list")
                    continue
                item_secrets: dict[str, str] = {}
                item_warnings: list[str] = []
                for field in fields:
                    if not isinstance(field, dict):
                        continue
                    if field.get("type") != _HIDDEN_FIELD_TYPE:
                        continue
                    name, value = field.get("name"), field.get("value")
                    if not isinstance(name, str) or not is_valid_env_name(name):
                        item_warnings.append(
                            "Skipped a Vaultwarden custom field with an invalid env-var name"
                        )
                    elif not isinstance(value, str) or not value:
                        item_warnings.append(
                            f"Skipped empty Vaultwarden custom field {name}"
                        )
                    elif name in item_secrets:
                        item_warnings.append(
                            f"Skipped duplicate Vaultwarden custom field {name}"
                        )
                    else:
                        item_secrets[name] = value
                if any(name in result.secrets for name in item_secrets):
                    result.warnings.append(
                        "Skipped Vaultwarden item because it conflicts with an earlier item"
                    )
                    continue
                result.warnings.extend(item_warnings)
                result.secrets.update(item_secrets)
        finally:
            _release_runtime_lock(lock_fd)
        return result

    def _bootstrap_if_needed(
        self, binary: Path, cfg: dict, runtime_dir: Path, deadline: float
    ) -> tuple[str, dict[str, str]] | ErrorKind:
        if self._bootstrap_session:
            return self._bootstrap_session, self._bootstrap_env
        runtime_env = _runtime_env_for(runtime_dir)
        session = _read_runtime_session(runtime_dir)
        if session:
            self._bootstrap_session = session
            self._bootstrap_env = runtime_env
            return session, runtime_env
        return self._bootstrap(binary, cfg, runtime_dir, deadline)

    def _bootstrap(
        self, binary: Path, cfg: dict, runtime_dir: Path, deadline: float
    ) -> tuple[str, dict[str, str]] | ErrorKind:
        """Log in and unlock from a clean slate. Starting from nothing every
        time keeps any earlier failure (wrong password, timeout, a process
        killed mid-login) from leaving bw state that blocks the next attempt."""
        credentials = _read_bootstrap_credentials(cfg)
        server_url = str(cfg.get("server_url") or "").strip()
        if credentials is None or not server_url.startswith("https://"):
            return ErrorKind.NOT_CONFIGURED

        _invalidate_runtime_bootstrap(runtime_dir)
        runtime_env = _runtime_env_for(runtime_dir)
        configured = _run_cli(
            binary, ["config", "server", server_url], runtime_env, deadline
        )
        if configured is None or configured.returncode != 0:
            return _error_kind(configured, deadline)
        observed_server = _run_cli(binary, ["config", "server"], runtime_env, deadline)
        if observed_server is None or observed_server.returncode != 0:
            return _error_kind(observed_server, deadline)
        if not _same_server_url(observed_server.stdout, server_url):
            # Never send the API key to a server we did not configure.
            return ErrorKind.AUTH_FAILED
        logged_in = _run_cli(
            binary,
            ["login", "--apikey"],
            {
                **runtime_env,
                "BW_CLIENTID": credentials["client_id"],
                "BW_CLIENTSECRET": credentials["client_secret"],
            },
            deadline,
        )
        if logged_in is None or logged_in.returncode != 0:
            return _error_kind(logged_in, deadline)
        unlocked = _run_cli(
            binary,
            ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
            {**runtime_env, "BW_PASSWORD": credentials["password"]},
            deadline,
        )
        if unlocked is None or unlocked.returncode != 0:
            return _error_kind(unlocked, deadline)
        session = unlocked.stdout.strip()
        if not session or not _write_runtime_session(runtime_dir, session):
            return ErrorKind.INTERNAL
        self._bootstrap_session = session
        self._bootstrap_env = runtime_env
        return session, runtime_env

    def _clear_bootstrap(self) -> None:
        self._bootstrap_session = None
        self._bootstrap_env = {}


def _runtime_dir(cfg: dict) -> Optional[Path]:
    value = str((cfg or {}).get("runtime_dir") or _DEFAULT_RUNTIME_DIR).strip()
    path = Path(value)
    return path if path.is_absolute() else None


def _runtime_env_for(runtime_dir: Path) -> dict[str, str]:
    """Isolate bw's config/session state to ``runtime_dir``. ``HOME`` alone is
    not enough: ``run_secret_cli`` forwards ambient XDG_* vars, which some
    env-paths resolvers (bw is Node-based) prefer over HOME on Linux."""
    return {
        "HOME": str(runtime_dir),
        "XDG_CONFIG_HOME": str(runtime_dir),
        "XDG_DATA_HOME": str(runtime_dir),
        "BITWARDENCLI_APPDATA_DIR": str(_bw_state_dir(runtime_dir)),
    }


def find_bw(home_path: Path, configured_binary: str = "") -> Optional[Path]:
    """Find a deliberately installed ``bw`` binary; never auto-download one."""
    candidates: list[Path] = []
    if configured_binary:
        candidate = Path(configured_binary)
        if not candidate.is_absolute():
            return None
        candidates.append(candidate)
    else:
        candidates.append(home_path / "bin" / "bw")
        discovered = shutil.which("bw")
        if discovered:
            candidates.append(Path(discovered))
    return next(
        (path for path in candidates if path.is_file() and os.access(path, os.X_OK)),
        None,
    )


def _run_bw(
    binary: Path,
    args: list[str],
    session: str,
    extra_env: dict[str, str],
    deadline: float,
):
    # bw only reads BW_SESSION; the child env is built from scratch, so there is
    # no name to collide with whatever session_env is configured.
    return _run_cli(binary, args, {**extra_env, "BW_SESSION": session}, deadline)


def _run_cli(binary: Path, args: list[str], extra_env: dict[str, str], deadline: float):
    remaining = _remaining_seconds(deadline)
    if remaining is None:
        return None
    try:
        return run_secret_cli(
            [str(binary), *args],
            allow_env=_BW_PASSTHROUGH_ENV,
            extra_env=extra_env,
            timeout=remaining,
        )
    except RuntimeError:
        return None


def _same_server_url(observed: str, configured: str) -> bool:
    return observed.strip().rstrip("/") == configured.rstrip("/")


def _resolve_bootstrap_value(raw: str) -> Optional[str]:
    """Resolve one bootstrap credential: ``file:///absolute/path`` reads a
    secret file, ``env:NAME`` reads this fetch's environment (``.env``
    included), and any other value is the literal credential itself."""
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith(_ENV_SCHEME_PREFIX):
        name = raw[len(_ENV_SCHEME_PREFIX):].strip()
        if not is_valid_env_name(name):
            return None
        return get_source_environment().get(name, "").strip() or None
    if not raw.startswith(_FILE_SCHEME_PREFIX):
        return raw
    path = Path(raw[len(_FILE_SCHEME_PREFIX):])
    if not path.is_absolute():
        return None
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _read_bootstrap_credentials(cfg: dict) -> Optional[dict[str, str]]:
    raw_values = {
        "client_id": str(cfg.get("client_id") or ""),
        "client_secret": str(cfg.get("client_secret") or ""),
        "password": str(cfg.get("master_password") or ""),
    }
    credentials: dict[str, str] = {}
    for name, raw in raw_values.items():
        resolved = _resolve_bootstrap_value(raw)
        if resolved is None:
            return None
        credentials[name] = resolved
    return credentials


def _bootstrap_env_refs(cfg: dict) -> set[str]:
    refs = set()
    for key in _BOOTSTRAP_KEYS:
        raw = str((cfg or {}).get(key) or "").strip()
        if raw.startswith(_ENV_SCHEME_PREFIX):
            name = raw[len(_ENV_SCHEME_PREFIX):].strip()
            if is_valid_env_name(name):
                refs.add(name)
    return refs


# Only a whole ``${NAME}`` / ``${env:NAME}`` value, the shape Hermes uses: a
# random literal password may well contain "${" somewhere.
_PLACEHOLDER_RE = re.compile(r"\$\{\s*(?:env:)?\s*[A-Za-z_][A-Za-z0-9_]*\s*\}")


def _unexpanded_placeholder(cfg: dict) -> Optional[str]:
    """Hermes passes the secrets: section verbatim, so a ``${VAR}`` would
    otherwise be sent to Vaultwarden as the literal credential."""
    for key in ("server_url", *_BOOTSTRAP_KEYS):
        if _PLACEHOLDER_RE.fullmatch(str((cfg or {}).get(key) or "").strip()):
            return key
    return None


def _is_transient(result: FetchResult) -> bool:
    """Worth retrying: any error but a permanent one, or no secrets at all
    because every item read failed."""
    if result.error:
        return result.error_kind not in _PERMANENT_ERRORS
    return not result.secrets and bool(result.warnings)


def _error_kind(result, deadline: float) -> ErrorKind:
    if _remaining_seconds(deadline) is None:
        return ErrorKind.TIMEOUT
    return _classify_error(result.stderr if result is not None else "")


# First match wins. Network failures are checked before credential ones so a
# stray "401" inside an address or port never turns an outage into a
# (non-retried) AUTH_FAILED.
_ERROR_RULES = (
    (
        ErrorKind.AUTH_EXPIRED,
        ("session expired", "vault is locked", "not logged in", "invalid session"),
    ),
    (
        ErrorKind.NETWORK,
        (
            "network",
            "connection",
            "resolve",
            "dns",
            "server unavailable",
            "econnrefused",
            "econnreset",
            "enotfound",
            "etimedout",
            "socket hang up",
            "fetch failed",
        ),
    ),
    (
        ErrorKind.AUTH_FAILED,
        (
            "unauthorized",
            "forbidden",
            "invalid password",
            "invalid master password",
            "decryption operation failed",  # bw 2026.x on a wrong master password
            # Vaultwarden's API-key login rejections (src/api/identity.rs)
            "incorrect client_secret",
            "invalid client_id",
            "malformed client_id",
            "user has been disabled",
            "401",
            "403",
        ),
    ),
    (ErrorKind.TIMEOUT, ("timed out",)),
)


def _classify_error(message: str) -> ErrorKind:
    return classify_cli_error(message or "", _ERROR_RULES)
