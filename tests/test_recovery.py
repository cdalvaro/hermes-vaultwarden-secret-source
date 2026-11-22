"""Recovery tests against a stateful fake ``bw`` (tests/fake_bw.py).

Nothing here mocks ``run_secret_cli``: the plugin spawns the fake exactly as
it would spawn the real CLI, so the fake's state rules (no ``config server``
while logged in, a new session key per unlock) catch recovery paths that a
list of canned responses cannot. Each ``VaultwardenSource()`` stands for one
Hermes process in the same container task (same runtime_dir).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_DIR))

from agent.secret_sources.base import ErrorKind  # noqa: E402

import vaultwarden_source as vw  # noqa: E402

FAKE_BW = Path(__file__).with_name("fake_bw.py")
ITEM_ID = "6a1bd36e-77a2-42ba-8505-6f7c3a562d6b"
SERVER = "https://vaultwarden.example.test"
CREDENTIALS = {
    "client_id": "client-id",
    "client_secret": "client-secret",
    "master_password": "master-password",
}


@pytest.fixture(autouse=True)
def _no_retry_delay():
    with patch.object(vw.time, "sleep"):
        yield


@pytest.fixture
def task(tmp_path: Path):
    """One container task: a runtime dir with the fake's spec and log."""
    if not os.access(FAKE_BW, os.X_OK):
        FAKE_BW.chmod(0o755)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    (runtime / "fake.json").write_text(
        json.dumps(
            {
                "credentials": CREDENTIALS,
                "item_id": ITEM_ID,
                "fields": [{"name": "OPENAI_API_KEY", "value": "sk-vault", "type": 1}],
            }
        )
    )

    class Task:
        dir = runtime

        def cfg(self, **overrides) -> dict:
            return {
                "enabled": True,
                "binary": str(FAKE_BW),
                "server_url": SERVER,
                "runtime_dir": str(runtime),
                "item_ids": [ITEM_ID],
                **CREDENTIALS,
                **overrides,
            }

        def calls(self) -> list[list[str]]:
            log = runtime / "bw.log"
            if not log.exists():
                return []
            return [json.loads(line)["args"] for line in log.read_text().splitlines()]

        def logins(self) -> int:
            return sum(args[:1] == ["login"] for args in self.calls())

        def spec(self, **changes) -> None:
            path = runtime / "fake.json"
            path.write_text(json.dumps({**json.loads(path.read_text()), **changes}))

    return Task()


def fetch(cfg: dict, home: Path):
    source = vw.VaultwardenSource()
    try:
        return source.fetch(cfg, home)
    finally:
        source._clear_bootstrap()


def test_recovers_after_a_failed_unlock_once_the_password_is_fixed(task, tmp_path):
    failed = fetch(task.cfg(master_password="wrong"), tmp_path)
    assert failed.secrets == {}
    assert failed.error_kind == ErrorKind.AUTH_FAILED
    assert task.logins() == 1  # rejected credentials are not retried

    fixed = fetch(task.cfg(), tmp_path)

    assert fixed.error is None
    assert fixed.secrets == {"OPENAI_API_KEY": "sk-vault"}


def test_adopts_a_session_another_process_already_replaced(task, tmp_path):
    source = vw.VaultwardenSource()
    assert source.fetch(task.cfg(), tmp_path).secrets  # holds session #1
    # Another process re-unlocks: bw mints session #2 and shares it.
    env = {
        **vw._runtime_env_for(task.dir),
        "PATH": os.environ.get("PATH", ""),
        "BW_PASSWORD": CREDENTIALS["master_password"],
    }
    rotated = subprocess.run(
        [str(FAKE_BW), "unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    (task.dir / "session").write_text(rotated)

    again = source.fetch(task.cfg(), tmp_path)
    source._clear_bootstrap()

    assert again.secrets == {"OPENAI_API_KEY": "sk-vault"}
    assert task.logins() == 1
    assert (task.dir / "session").read_text() == rotated


def test_reauthenticates_from_scratch_when_the_shared_session_is_dead(task, tmp_path):
    assert fetch(task.cfg(), tmp_path).secrets
    state = task.dir / ".bitwarden" / "data.json"
    state.write_text(json.dumps({**json.loads(state.read_text()), "session": "gone"}))

    result = fetch(task.cfg(), tmp_path)

    assert result.secrets == {"OPENAI_API_KEY": "sk-vault"}
    assert task.logins() == 2


def test_unexpanded_placeholder_is_rejected_before_running_bw(task, tmp_path):
    result = fetch(task.cfg(master_password="${HERMES_VW_PASSWORD}"), tmp_path)

    assert result.error_kind == ErrorKind.NOT_CONFIGURED
    assert "master_password" in result.error and "env:NAME" in result.error
    assert task.calls() == []


def test_env_reference_reads_the_fetch_environment_and_is_protected(task, tmp_path):
    cfg = task.cfg(master_password="env:HERMES_VW_PASSWORD")
    with patch.dict(os.environ, {"HERMES_VW_PASSWORD": "master-password"}):
        result = fetch(cfg, tmp_path)

    assert result.secrets == {"OPENAI_API_KEY": "sk-vault"}
    assert "HERMES_VW_PASSWORD" in vw.VaultwardenSource().protected_env_vars(cfg)


def test_custom_session_env_still_reaches_bw_as_bw_session(task, tmp_path):
    result = fetch(task.cfg(session_env="HERMES_BW_SESSION"), tmp_path)

    assert result.secrets == {"OPENAI_API_KEY": "sk-vault"}
    assert task.logins() == 1


def test_an_unreachable_server_is_a_retried_network_error(task, tmp_path):
    task.spec(login_error="request to https://vaultwarden.example.test failed, reason: connect ECONNREFUSED 10.0.0.1:4013")

    result = fetch(task.cfg(), tmp_path)

    assert result.error_kind == ErrorKind.NETWORK
    assert task.logins() == vw._MAX_ATTEMPTS


def test_non_canonical_item_ids_reach_bw_canonically(task, tmp_path):
    spelled = "{" + ITEM_ID.upper() + "}"

    result = fetch(task.cfg(item_ids=[spelled]), tmp_path)

    assert result.secrets == {"OPENAI_API_KEY": "sk-vault"}
    assert ["get", "item", ITEM_ID] in task.calls()


def test_private_ca_bundle_is_forwarded_to_bw(task, tmp_path):
    with patch.dict(os.environ, {"NODE_EXTRA_CA_CERTS": "/etc/ssl/private-ca.pem"}):
        fetch(task.cfg(), tmp_path)

    log = (task.dir / "bw.log").read_text().splitlines()
    assert log and all(json.loads(line)["ca"] for line in log)
