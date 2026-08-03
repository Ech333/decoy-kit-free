"""Decoy Kit Free: a real SSH key honeytoken trap, free forever - the same module that ships
inside the paid Decoy Kit (northstartproductionstudio.com/decoy-kit), given away in full.

Self-hosted, same as the paid product: you run the receiver (`decoy-kit-free serve`), you plant
the key. No account, no signup, no telemetry - this package makes no network calls of its own
beyond what you configure."""

from . import ghost_schema
from .ssh_key_trap import SshKeyPlant, generate_ssh_key_trap
from .beacon import check_plant_hit, extract_plant_id_from_query

__all__ = [
    "ghost_schema",
    "SshKeyPlant",
    "generate_ssh_key_trap",
    "check_plant_hit",
    "extract_plant_id_from_query",
]

__version__ = "0.1.0"
