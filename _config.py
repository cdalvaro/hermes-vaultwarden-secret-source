"""Pure config-parsing helpers for the Vaultwarden secret source.

Split out because they are small, self-contained validators with no I/O --
easy to read and test in isolation from the CLI-invocation logic.
"""

from __future__ import annotations

import uuid
from typing import Optional

DEFAULT_SESSION_ENV = "BW_SESSION"


def item_ids(cfg: dict) -> Optional[list[str]]:
    """Canonical (lowercase, hyphenated) item UUIDs. bw only looks an item up by
    id when the argument matches its GUID pattern; anything else becomes a
    text search over item names, so never pass the user's spelling through."""
    configured_item_ids = (cfg or {}).get("item_ids")
    if not isinstance(configured_item_ids, list) or not configured_item_ids:
        return None
    ids: list[str] = []
    for configured in configured_item_ids:
        canonical = canonical_uuid(configured)
        if canonical is None or canonical in ids:
            return None
        ids.append(canonical)
    return ids


def session_env(cfg: dict) -> str:
    return str((cfg or {}).get("session_env") or DEFAULT_SESSION_ENV)


def canonical_uuid(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return str(uuid.UUID(value.strip()))
    except ValueError:
        return None
