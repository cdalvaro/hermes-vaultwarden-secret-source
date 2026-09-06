"""Vaultwarden secret source plugin for Hermes."""

from .vaultwarden_source import VaultwardenSource


def register(ctx) -> None:
    """Register the source.

    Hermes re-pulls enabled plugin secret sources automatically right after
    plugin discovery (``reset_secret_source_cache()`` +
    ``load_hermes_dotenv()``), so the discovering process picks up Vaultwarden
    credentials without this plugin re-running the loader itself.
    """
    ctx.register_secret_source(VaultwardenSource())
