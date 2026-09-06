"""Contract-conformance checks for VaultwardenSource.

Subclasses the official kit shipped with hermes-agent
(``tests.secret_sources.conformance.SecretSourceConformance``), per the
Secret Source Plugin guide -- "the review bar for calling a backend
contract-compliant". Requires PYTHONPATH to include a hermes-agent checkout,
same as the rest of this suite; see the README's Local validation section.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_DIR))

from tests.secret_sources.conformance import SecretSourceConformance  # noqa: E402

import vaultwarden_source as vw  # noqa: E402


class TestVaultwardenConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self) -> vw.VaultwardenSource:
        return vw.VaultwardenSource()
