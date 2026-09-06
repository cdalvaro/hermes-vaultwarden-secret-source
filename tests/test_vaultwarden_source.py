"""Hermetic tests for the Vaultwarden Hermes secret-source plugin."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_DIR))

from agent.secret_sources.base import ErrorKind  # noqa: E402
from agent.secret_sources.registry import (  # noqa: E402
    _reset_registry_for_tests,
    apply_all,
    register_source,
)

import vaultwarden_source as vw  # noqa: E402


class TestVaultwardenSource:
    item_id = "6a1bd36e-77a2-42ba-8505-6f7c3a562d6b"
    second_item_id = "f52cc80c-e62e-43dc-a2bb-eedee8ea1d91"
    third_item_id = "0feb3da2-e89f-4129-a08c-e18ca019a6da"

    def setup_method(self) -> None:
        self.source = vw.VaultwardenSource()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.home = Path(self.tmpdir.name)
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()

    def teardown_method(self) -> None:
        self.source._clear_bootstrap()
        self.env_patch.stop()
        self.tmpdir.cleanup()

    def bootstrap_cfg(self) -> dict[str, Any]:
        secret_dir = self.home / "secrets"
        secret_dir.mkdir(exist_ok=True)
        paths = {
            "client_id": secret_dir / "client-id",
            "client_secret": secret_dir / "client-secret",
            "master_password": secret_dir / "master-password",
        }
        for path, value in zip(
            paths.values(), ("client-id", "client-secret", "master-password")
        ):
            path.write_text(value, encoding="utf-8")
        return {
            "enabled": True,
            "item_ids": [self.item_id],
            "server_url": "https://vaultwarden.example.test",
            "runtime_dir": str(self.home / "runtime"),
            **{key: f"file://{path}" for key, path in paths.items()},
        }

    def bootstrap_responses(
        self, session: str
    ) -> list[subprocess.CompletedProcess[str]]:
        return [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="https://vaultwarden.example.test\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps({"status": "unauthenticated"}),
                stderr="",
            ),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=session, stderr=""
            ),
        ]

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_missing_bootstrap_credentials_never_runs_bw(
        self, run_cli, _find_bw
    ) -> None:
        cfg = {
            "enabled": True,
            "item_ids": [self.item_id],
            "runtime_dir": str(self.home / "runtime"),
            "client_id": f"file://{self.home / 'missing-client-id'}",
            "client_secret": f"file://{self.home / 'missing-client-secret'}",
            "master_password": f"file://{self.home / 'missing-password'}",
        }
        result = self.source.fetch(cfg, self.home)

        assert result.error_kind == ErrorKind.NOT_CONFIGURED
        run_cli.assert_not_called()

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_bootstrap_credentials_can_be_literal_values(
        self, run_cli, _find_bw
    ) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
        ]
        cfg = {
            **self.bootstrap_cfg(),
            "client_id": "literal-client-id",
            "client_secret": "literal-client-secret",
            "master_password": "literal-master-password",
        }

        result = self.source.fetch(cfg, self.home)

        assert result.secrets == {}
        login_env = run_cli.call_args_list[3].kwargs["extra_env"]
        unlock_env = run_cli.call_args_list[4].kwargs["extra_env"]
        assert login_env["BW_CLIENTID"] == "literal-client-id"
        assert login_env["BW_CLIENTSECRET"] == "literal-client-secret"
        assert unlock_env["BW_PASSWORD"] == "literal-master-password"

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_bootstrap_credentials_can_mix_literal_and_file(
        self, run_cli, _find_bw
    ) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
        ]
        cfg = {**self.bootstrap_cfg(), "client_id": "literal-client-id"}

        result = self.source.fetch(cfg, self.home)

        assert result.secrets == {}
        login_env = run_cli.call_args_list[3].kwargs["extra_env"]
        assert login_env["BW_CLIENTID"] == "literal-client-id"
        assert login_env["BW_CLIENTSECRET"] == "client-secret"

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_relative_file_reference_is_not_configured(
        self, run_cli, _find_bw
    ) -> None:
        cfg = {**self.bootstrap_cfg(), "client_id": "file://relative/path"}

        result = self.source.fetch(cfg, self.home)

        assert result.error_kind == ErrorKind.NOT_CONFIGURED
        run_cli.assert_not_called()

    def test_missing_item_ids_is_not_configured(self) -> None:
        result = self.source.fetch({"enabled": True}, self.home)
        assert result.error_kind == ErrorKind.NOT_CONFIGURED

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_bootstrap_fails_closed_when_server_configuration_does_not_persist(
        self, run_cli, _find_bw
    ) -> None:
        calls: list[list[str]] = []

        def fake_run(command, *, extra_env, timeout):
            args = command[1:]
            calls.append(args)
            if args == ["config", "server", "https://vaultwarden.example.test"]:
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                )
            if args == ["config", "server"]:
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="https://other.example.test\n",
                    stderr="",
                )
            pytest.fail(
                "Bootstrap credentials must not be sent after server verification fails"
            )

        run_cli.side_effect = fake_run
        result = self.source.fetch(self.bootstrap_cfg(), self.home)

        assert result.error_kind == ErrorKind.AUTH_FAILED
        assert calls == [
            ["config", "server", "https://vaultwarden.example.test"],
            ["config", "server"],
        ]

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_locked_cli_state_unlocks_without_reauthenticating(
        self, run_cli, _find_bw
    ) -> None:
        calls: list[list[str]] = []

        def fake_run(command, *, extra_env, timeout):
            args = command[1:]
            calls.append(args)
            if args == ["config", "server", "https://vaultwarden.example.test"]:
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                )
            if args == ["config", "server"]:
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="https://vaultwarden.example.test\n",
                    stderr="",
                )
            if args == ["status", "--raw"]:
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps({"status": "locked"}),
                    stderr="",
                )
            if args == ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"]:
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="session", stderr=""
                )
            if args == ["sync"]:
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                )
            if args == ["get", "item", self.item_id]:
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
                )
            pytest.fail(f"Unexpected bw invocation: {args}")

        run_cli.side_effect = fake_run
        result = self.source.fetch(self.bootstrap_cfg(), self.home)

        assert result.secrets == {}
        assert ["login", "--apikey"] not in calls
        assert calls == [
            ["config", "server", "https://vaultwarden.example.test"],
            ["config", "server"],
            ["status", "--raw"],
            ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
            ["sync"],
            ["get", "item", self.item_id],
        ]

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_unexpected_cli_state_fails_closed_without_sending_credentials(
        self, run_cli, _find_bw
    ) -> None:
        calls: list[list[str]] = []

        def fake_run(command, *, extra_env, timeout):
            args = command[1:]
            calls.append(args)
            if args == ["config", "server", "https://vaultwarden.example.test"]:
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                )
            if args == ["config", "server"]:
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="https://vaultwarden.example.test\n",
                    stderr="",
                )
            if args == ["status", "--raw"]:
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps({"status": "unlocked"}),
                    stderr="",
                )
            pytest.fail(
                "Bootstrap credentials must not be sent for an unexpected CLI state"
            )

        run_cli.side_effect = fake_run
        result = self.source.fetch(self.bootstrap_cfg(), self.home)

        assert result.error_kind == ErrorKind.AUTH_FAILED
        assert calls == [
            ["config", "server", "https://vaultwarden.example.test"],
            ["config", "server"],
            ["status", "--raw"],
        ]

    def test_protects_session_and_bootstrap_environment_names(self) -> None:
        assert self.source.protected_env_vars({}) == frozenset(
            {"BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"}
        )

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_only_hidden_custom_fields_are_consumed(self, run_cli, _find_bw) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "fields": [
                            {"name": "TEXT_FIELD", "value": "visible", "type": 0},
                            {"name": "HIDDEN_FIELD", "value": "secret", "type": 1},
                            {"name": "BOOLEAN_FIELD", "value": "true", "type": 2},
                        ]
                    }
                ),
                stderr="",
            ),
        ]

        result = self.source.fetch(self.bootstrap_cfg(), self.home)

        assert result.secrets == {"HIDDEN_FIELD": "secret"}

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_item_ids_load_all_items_after_one_sync(self, run_cli, _find_bw) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "fields": [
                            {"name": "OPENAI_API_KEY", "value": "openai", "type": 1}
                        ]
                    }
                ),
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "fields": [
                            {
                                "name": "ANTHROPIC_API_KEY",
                                "value": "anthropic",
                                "type": 1,
                            }
                        ]
                    }
                ),
                stderr="",
            ),
        ]
        cfg = {**self.bootstrap_cfg(), "item_ids": [self.item_id, self.second_item_id]}

        result = self.source.fetch(cfg, self.home)

        assert result.secrets == {
            "OPENAI_API_KEY": "openai",
            "ANTHROPIC_API_KEY": "anthropic",
        }
        assert [call.args[0][1:] for call in run_cli.call_args_list] == [
            ["config", "server", "https://vaultwarden.example.test"],
            ["config", "server"],
            ["status", "--raw"],
            ["login", "--apikey"],
            ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
            ["sync"],
            ["get", "item", self.item_id],
            ["get", "item", self.second_item_id],
        ]

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_item_ids_skip_an_entire_item_when_any_field_collides(
        self, run_cli, _find_bw
    ) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "fields": [
                            {"name": "OPENAI_API_KEY", "value": "first", "type": 1}
                        ]
                    }
                ),
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "fields": [
                            {"name": "ANTHROPIC_API_KEY", "value": "second", "type": 1},
                            {"name": "OPENAI_API_KEY", "value": "collision", "type": 1},
                        ]
                    }
                ),
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {"fields": [{"name": "GITHUB_TOKEN", "value": "third", "type": 1}]}
                ),
                stderr="",
            ),
        ]
        cfg = {
            **self.bootstrap_cfg(),
            "item_ids": [self.item_id, self.second_item_id, self.third_item_id],
        }

        result = self.source.fetch(cfg, self.home)

        assert result.secrets == {"OPENAI_API_KEY": "first", "GITHUB_TOKEN": "third"}
        assert result.warnings == [
            "Skipped Vaultwarden item because it conflicts with an earlier item"
        ]

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    def test_legacy_item_id_is_not_configured(self, _find_bw) -> None:
        result = self.source.fetch(
            {"enabled": True, "item_id": self.item_id}, self.home
        )

        assert result.error_kind == ErrorKind.NOT_CONFIGURED

    @pytest.mark.parametrize("item_ids", [[], [item_id, item_id], ["not-a-uuid"]])
    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    def test_item_ids_must_be_unique_vaultwarden_uuids(
        self, _find_bw, item_ids
    ) -> None:
        result = self.source.fetch({"enabled": True, "item_ids": item_ids}, self.home)
        assert result.error_kind == ErrorKind.NOT_CONFIGURED

    @patch.object(vw, "find_bw", return_value=None)
    def test_missing_binary_is_reported(self, _find_bw) -> None:
        result = self.source.fetch(
            {"enabled": True, "item_ids": [self.item_id]}, self.home
        )
        assert result.error_kind == ErrorKind.BINARY_MISSING

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_bootstraps_once_into_the_container_runtime_directory(
        self, run_cli, _find_bw
    ) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("fresh-session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "fields": [
                            {"name": "OPENAI_API_KEY", "value": "from-vault", "type": 1}
                        ]
                    }
                ),
                stderr="",
            ),
        ]

        cfg = self.bootstrap_cfg()
        result = self.source.fetch(cfg, self.home)

        assert result.secrets == {"OPENAI_API_KEY": "from-vault"}
        assert "BW_SESSION" not in os.environ
        assert [call.args[0][1:] for call in run_cli.call_args_list] == [
            ["config", "server", "https://vaultwarden.example.test"],
            ["config", "server"],
            ["status", "--raw"],
            ["login", "--apikey"],
            ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
            ["sync"],
            ["get", "item", self.item_id],
        ]
        (
            config_env,
            observed_server_env,
            status_env,
            login_env,
            unlock_env,
            sync_env,
            get_env,
        ) = [call.kwargs["extra_env"] for call in run_cli.call_args_list]
        homes = {
            env["HOME"]
            for env in (
                config_env,
                observed_server_env,
                status_env,
                login_env,
                unlock_env,
                sync_env,
                get_env,
            )
        }
        assert homes == {str(cfg["runtime_dir"])}
        session_path = Path(str(cfg["runtime_dir"])) / "session"
        assert session_path.read_text(encoding="utf-8") == "fresh-session"
        assert session_path.stat().st_mode & 0o777 == 0o600
        assert login_env["BW_CLIENTID"] == "client-id"
        assert "BW_PASSWORD" not in login_env
        assert unlock_env["BW_PASSWORD"] == "master-password"
        assert "BW_CLIENTSECRET" not in unlock_env
        assert sync_env["BW_SESSION"] == "fresh-session"
        assert "BW_PASSWORD" not in sync_env

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    @patch.object(vw.time, "monotonic", side_effect=range(8))
    def test_uses_one_declining_deadline_for_the_full_fetch(
        self, _clock, run_cli, _find_bw
    ) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
        ]

        result = self.source.fetch(
            {**self.bootstrap_cfg(), "timeout_seconds": 30}, self.home
        )

        assert result.secrets == {}
        assert [call.kwargs["timeout"] for call in run_cli.call_args_list] == [
            29,
            28,
            27,
            26,
            25,
            24,
            23,
        ]

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_shares_bootstrap_across_source_instances(self, run_cli, _find_bw) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("shared-session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
        ]
        cfg = self.bootstrap_cfg()
        other_source = vw.VaultwardenSource()

        self.source.fetch(cfg, self.home)
        other_source.fetch(cfg, self.home)
        other_source._clear_bootstrap()

        assert [call.args[0][1] for call in run_cli.call_args_list] == [
            "config",
            "config",
            "status",
            "login",
            "unlock",
            "sync",
            "get",
            "sync",
            "get",
        ]

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_replaces_an_expired_shared_session_once(self, run_cli, _find_bw) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("expired-session"),
            subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="session expired"
            ),
            *self.bootstrap_responses("replacement-session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
        ]
        cfg = self.bootstrap_cfg()
        other_source = vw.VaultwardenSource()

        self.source.fetch(cfg, self.home)
        other_source.fetch(cfg, self.home)
        other_source._clear_bootstrap()

        assert [call.args[0][1] for call in run_cli.call_args_list].count("login") == 2
        session_path = Path(str(cfg["runtime_dir"])) / "session"
        assert session_path.read_text(encoding="utf-8") == "replacement-session"

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_serializes_parallel_bootstraps_through_one_shared_login(
        self, run_cli, _find_bw
    ) -> None:
        calls: list[str] = []
        calls_lock = threading.Lock()

        def fake_run(command, *, extra_env, timeout):
            args = command[1:]
            action = args[0]
            with calls_lock:
                calls.append(action)
            if args == ["config", "server", "https://vaultwarden.example.test"]:
                time.sleep(0.05)
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                )
            if args == ["config", "server"]:
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="https://vaultwarden.example.test\n",
                    stderr="",
                )
            if args == ["status", "--raw"]:
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps({"status": "unauthenticated"}),
                    stderr="",
                )
            if action == "unlock":
                return subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="shared-session", stderr=""
                )
            if action == "get":
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps(
                        {
                            "fields": [
                                {
                                    "name": "OPENAI_API_KEY",
                                    "value": "from-vault",
                                    "type": 1,
                                }
                            ]
                        }
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )

        run_cli.side_effect = fake_run
        cfg = self.bootstrap_cfg()
        sources = [vw.VaultwardenSource() for _ in range(5)]

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(sources)
        ) as executor:
            results = list(
                executor.map(lambda source: source.fetch(cfg, self.home), sources)
            )
        for source in sources:
            source._clear_bootstrap()

        assert all(
            result.secrets == {"OPENAI_API_KEY": "from-vault"} for result in results
        )
        assert calls.count("login") == 1
        assert calls.count("unlock") == 1
        assert calls.count("sync") == len(sources)
        assert calls.count("get") == len(sources)

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_reuses_bootstrap_within_one_source_instance(
        self, run_cli, _find_bw
    ) -> None:
        first = [
            *self.bootstrap_responses("session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
        ]
        second = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"fields": []}), stderr=""
            ),
        ]
        run_cli.side_effect = first + second
        cfg = self.bootstrap_cfg()

        self.source.fetch(cfg, self.home)
        self.source.fetch(cfg, self.home)

        assert [call.args[0][1] for call in run_cli.call_args_list] == [
            "config",
            "config",
            "status",
            "login",
            "unlock",
            "sync",
            "get",
            "sync",
            "get",
        ]

    @patch.object(vw, "find_bw", return_value=Path("/usr/local/bin/bw"))
    @patch.object(vw, "run_secret_cli")
    def test_registry_protects_legacy_session_field(
        self, run_cli, _find_bw, request
    ) -> None:
        run_cli.side_effect = [
            *self.bootstrap_responses("session"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "fields": [
                            {"name": "BW_SESSION", "value": "no", "type": 1},
                            {"name": "OPENAI_API_KEY", "value": "yes", "type": 1},
                        ]
                    }
                ),
                stderr="",
            ),
        ]
        _reset_registry_for_tests()
        request.addfinalizer(_reset_registry_for_tests)
        assert register_source(self.source)
        environment = {"BW_SESSION": "legacy"}

        report = apply_all(
            {"vaultwarden": self.bootstrap_cfg()}, self.home, environ=environment
        )

        assert environment["BW_SESSION"] == "legacy"
        assert environment["OPENAI_API_KEY"] == "yes"
        assert report.sources[0].skipped_protected == ["BW_SESSION"]

    def test_register_installs_the_source(self) -> None:
        """Hermes re-pulls enabled plugin sources on its own after discovery;
        this plugin's register(ctx) only needs to install the source."""
        init_path = PLUGIN_DIR / "__init__.py"
        spec = importlib.util.spec_from_file_location(
            "vaultwarden_plugin_test",
            init_path,
            submodule_search_locations=[str(PLUGIN_DIR)],
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)

        class Context:
            source: Any | None = None

            def register_secret_source(self, source) -> None:
                self.source = source

        context = Context()
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            module.register(context)
        finally:
            sys.modules.pop(spec.name, None)

        # Loaded under its own module identity here (vs. the flat `vw` import
        # used elsewhere in this file), so compare by class name, not isinstance.
        assert context.source is not None
        assert type(context.source).__name__ == "VaultwardenSource"
        assert context.source.name == "vaultwarden"
