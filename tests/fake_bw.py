#!/usr/bin/env python3
"""Stateful stand-in for the Bitwarden CLI.

Models the bw behaviours the plugin's recovery paths depend on (checked
against @bitwarden/cli 2026.x):

* account state persists in $BITWARDENCLI_APPDATA_DIR/data.json;
* ``config server <url>`` is refused while any account is logged in;
* every ``unlock`` mints a new session key, so older BW_SESSION values stop
  working;
* ``sync`` / ``get`` with a stale BW_SESSION report "Vault is locked.";
* ``get item`` treats a non-GUID argument as a text search.

Behaviour comes from $HOME/fake.json (``credentials``, ``item_id``,
``fields``, optional ``login_error``); every call is appended to
$HOME/bw.log because run_secret_cli forwards no arbitrary variables.
"""

import json
import os
import re
import secrets
import sys
from pathlib import Path

home = Path(os.environ["HOME"])
spec = json.loads((home / "fake.json").read_text())
state_path = Path(os.environ["BITWARDENCLI_APPDATA_DIR"]) / "data.json"
state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
state = json.loads(state_path.read_text()) if state_path.exists() else {}
args = sys.argv[1:]
with (home / "bw.log").open("a") as log:
    log.write(json.dumps({"args": args, "ca": "NODE_EXTRA_CA_CERTS" in os.environ}) + "\n")


def done(stdout="", code=0, stderr=""):
    state_path.write_text(json.dumps(state))
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    sys.exit(code)


unlocked = bool(state.get("session")) and os.environ.get("BW_SESSION") == state["session"]
good = spec["credentials"]

if args[:2] == ["config", "server"]:
    if len(args) == 2:
        done(state.get("server", "https://vault.bitwarden.com") + "\n")
    if state.get("account"):
        done(stderr="Logout required before server config update.\n", code=1)
    state["server"] = args[2]
    done("Saved setting `config`.\n")
if args[:2] == ["login", "--apikey"]:
    if spec.get("login_error"):
        done(stderr=spec["login_error"] + "\n", code=1)
    if state.get("account"):
        done(stderr="You are already logged in as hermes@example.test.\n", code=1)
    if (os.environ.get("BW_CLIENTID"), os.environ.get("BW_CLIENTSECRET")) != (
        good["client_id"],
        good["client_secret"],
    ):
        done(stderr="Incorrect client_secret\n", code=1)
    state["account"] = "hermes"
    done("You are logged in!\n")
if args[:1] == ["unlock"]:
    if not state.get("account"):
        done(stderr="You are not logged in.\n", code=1)
    if os.environ.get("BW_PASSWORD") != good["master_password"]:
        done(stderr="Cryptography error, The decryption operation failed\n", code=1)
    state["session"] = secrets.token_urlsafe(16)
    done(state["session"])
if args[:1] in (["sync"], ["get"]):
    if not state.get("account"):
        done(stderr="You are not logged in.\n", code=1)
    if not unlocked:
        done(stderr="Vault is locked.\n", code=1)
    if args[0] == "sync":
        done("Syncing complete.\n")
    guid = re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", args[2])
    if guid and args[2] == spec["item_id"]:
        done(json.dumps({"fields": spec["fields"]}))
    done(stderr="Not found.\n", code=1)
done(stderr=f"unsupported: {args}\n", code=2)
