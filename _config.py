"""Pure config-parsing helpers for the Vaultwarden secret source.

Split out because they are small, self-contained validators with no I/O --
easy to read and test in isolation from the CLI-invocation logic.
"""

from __future__ import annotations

import uuid
from typing import Optional

DEFAULT_SESSION_ENV = "BW_SESSION"


def item_ids(cfg: dict) -> Optional[list[str]]:
    configured_item_ids = (cfg or {}).get("item_ids")
    if not isinstance(configured_item_ids, list):
        return None
    ids = [
        item_id.strip() for item_id in configured_item_ids if isinstance(item_id, str)
    ]
    if len(ids) != len(configured_item_ids):
        return None
    if not ids or len(set(ids)) != len(ids) or not all(is_uuid(i) for i in ids):
        return None
    return ids


def session_env(cfg: dict) -> str:
    return str((cfg or {}).get("session_env") or DEFAULT_SESSION_ENV)


def is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except (TypeError, ValueError, AttributeError):
        return False
    return True
