"""Minimal FastAPI app that runs just Ghost-Schema's bait paths - the receiver the SSH key trap's
beacon URL needs to actually catch a hit. Requires fastapi + uvicorn (installed via the `[serve]`
extra: `pip install decoy-kit-free[serve]`) - the core trap modules themselves stay pure-stdlib.

`decoy-kit-free serve` runs this.
"""

import logging
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s | decoy-kit-free | %(levelname)s | %(message)s")
_log = logging.getLogger("decoy_kit_free")


def _resolve_seed(seed_hex: str | None) -> bytes:
    """Resolves the deployment seed from (in order): an explicit --seed-hex argument, the
    DECOY_KIT_FREE_SEED env var, or a freshly generated one - printed loudly so it can be saved,
    since losing it breaks beacon-hit correlation for every key already planted with the old
    seed."""
    import secrets

    if seed_hex:
        return bytes.fromhex(seed_hex)
    env_seed = os.environ.get("DECOY_KIT_FREE_SEED")
    if env_seed:
        return bytes.fromhex(env_seed)
    fresh = secrets.token_bytes(32)
    _log.warning(
        "No seed provided (--seed-hex or DECOY_KIT_FREE_SEED env var) - generated a fresh one "
        "for this run. SAVE IT: the key you planted with a different seed will only be "
        "recognized while this service uses the SAME seed. Set DECOY_KIT_FREE_SEED=%s to "
        "reuse it.",
        fresh.hex(),
    )
    return fresh


def build_app(seed_hex: str | None = None, siem_webhook=None):
    """Builds and returns the FastAPI app. `siem_webhook`, if given, is called as
    `siem_webhook(trap_name: str, detail: dict)` on every genuine hit - wire it to your own
    alerting however you like; this function has no opinion on where alerts go, only that they
    funnel through one place."""
    from fastapi import FastAPI

    from . import ghost_schema

    seed = _resolve_seed(seed_hex)
    app = FastAPI(title="Decoy Kit Free - SSH Key Trap", docs_url=None, redoc_url=None)

    def _alert(trap_name: str, **detail):
        _log.warning("TRAP TRIPPED [%s] %s", trap_name, detail)
        if siem_webhook:
            siem_webhook(trap_name, detail)

    app.add_middleware(
        ghost_schema.build_asgi_middleware(
            seed,
            on_hit=lambda path, source_id, response: _alert("ghost-schema", path=path, source_id=source_id),
        )
    )
    app.state.seed = seed
    return app
