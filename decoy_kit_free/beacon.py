"""Plant-id helpers shared by every plant-and-detect trap in this package: a per-plant identifier
embedded in the planted artifact's beacon URL, so a hit traces back to WHICH specific plant was
used, not just that some bait path was hit by someone. Stateless - the id lives in the request
itself, no registry needed to recognize a candidate.

Pure standard library.
"""

from __future__ import annotations

import urllib.parse


def extract_plant_id_from_query(url_or_query: str) -> str | None:
    """Pulls a plant id out of a request's URL/query string, or None if absent/malformed."""
    parsed = urllib.parse.urlparse(url_or_query)
    values = urllib.parse.parse_qs(parsed.query).get("plant")
    if not values:
        return None
    candidate = values[0]
    return candidate if candidate.startswith("chk_") else None


def check_plant_hit(url_or_query: str, planted_ids: set[str]) -> str | None:
    """Returns the plant id if `url_or_query` carries a genuine hit on a plant this caller
    actually made, else None. A trigger for a human look, not an automatic verdict on intent."""
    plant_id = extract_plant_id_from_query(url_or_query)
    if plant_id is None or plant_id not in planted_ids:
        return None
    return plant_id
