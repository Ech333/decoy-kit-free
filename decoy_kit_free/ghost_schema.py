"""Ghost-Schema - an API tarpit for scanner-bait paths.

Automated scanners probe common paths (/admin, /.env, /backup, ...) expecting either a real 404
(try elsewhere) or a real hit (exploit it). This returns neither: a 200 OK with plausible-looking,
but entirely fake, deterministic JSON - wasting the scanner's time on a payload that leads nowhere,
while logging the attempt. Deterministic (HMAC-seeded), not random, so repeated probes from the
same source see internally-consistent fake data rather than obviously-randomized noise.

Framework-agnostic core (`evaluate`), pure standard library. This is the receiver the SSH key
trap's beacon URL points at - you need this running somewhere for the trap to actually catch a
hit; it isn't optional supporting cast, it's the other half of the trap.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass


# Path -> fake payload template. Values containing "{n}" get a deterministic per-source token
# substituted in; this is what makes repeated hits from the same prober see consistent fake data
# instead of a fresh random blob every time (which would itself be a tell that it's fake).
_BAIT_PATHS: dict[str, dict] = {
    "/admin": {"status": "ok", "session": "adm_{n}", "role": "administrator"},
    "/.env": {
        "DATABASE_URL": "postgres://admin:{n}@db.internal:5432/prod",
        "AWS_SECRET_ACCESS_KEY": "{n}",
    },
    "/backup": {"files": ["backup_2026_01_{n}.tar.gz"], "status": "available"},
    "/backup.sql": {"status": "ok", "size_bytes": 41943040, "checksum": "{n}"},
    "/wp-admin": {"error": "login_required", "session_hint": "{n}"},
    "/.git/config": {
        "core": {"repositoryformatversion": 0},
        "remote": {"origin": {"url": "git@internal:{n}.git"}},
    },
    "/api/export": {"export_id": "exp_{n}", "status": "queued"},
    "/phpmyadmin": {"error": "access_denied", "trace_id": "{n}"},
}


@dataclass(frozen=True)
class GhostResponse:
    path: str
    payload: dict
    source_token: str  # deterministic per-source identifier, for correlating repeat hits in logs


def _source_token(seed: bytes, source_id: str) -> str:
    """Deterministic, non-reversible per-(seed, source) token - same source hitting the same
    tarpit always gets the same fake token, without the token revealing the real seed or source."""
    return hmac.new(seed, source_id.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _fill(template, token: str):
    if isinstance(template, dict):
        return {k: _fill(v, token) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, token) for v in template]
    if isinstance(template, str):
        return template.replace("{n}", token)
    return template


def is_bait_path(path: str) -> bool:
    return path in _BAIT_PATHS


def evaluate(path: str, source_id: str, seed: bytes) -> GhostResponse | None:
    """Returns a GhostResponse (fake payload, safe to send with a 200) if `path` is a registered
    bait path, else None (caller should fall through to its real 404/routing). `source_id` is
    whatever the caller uses to identify the requester (IP, a header, etc.) - never trusted for
    anything beyond making the fake response internally consistent across repeat hits."""
    template = _BAIT_PATHS.get(path)
    if template is None:
        return None
    token = _source_token(seed, source_id)
    return GhostResponse(path=path, payload=_fill(template, token), source_token=token)


def payload_json(response: GhostResponse) -> str:
    return json.dumps(response.payload, sort_keys=True)


# --- Optional FastAPI wrapper ------------------------------------------------------------------

def build_asgi_middleware(seed: bytes, on_hit=None):
    """Returns a Starlette/FastAPI-compatible middleware class. Import fastapi/starlette only
    inside this function, so this module has zero hard dependency on either - `evaluate()`/
    `is_bait_path()` above work with no framework at all.
    `on_hit(path, source_id, response, url)` is called (if given) whenever a bait path is hit.
    `url` is the full request URL (including query string) as a string - callers that plant a
    per-plant id in the query string (see `beacon.py`) need it to attribute the hit; this module
    itself stays agnostic to what, if anything, is in the query string."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    class GhostSchemaMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            path = request.url.path
            if is_bait_path(path):
                source_id = request.client.host if request.client else "unknown"
                response = evaluate(path, source_id, seed)
                if on_hit:
                    on_hit(path, source_id, response, str(request.url))
                return JSONResponse(response.payload, status_code=200)
            return await call_next(request)

    return GhostSchemaMiddleware
