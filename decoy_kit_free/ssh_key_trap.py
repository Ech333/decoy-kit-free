"""SSH Key Secret-Scanner Trap - a real, valid SSH private key with a beacon URL embedded in its
comment field, meant to catch automated secret scanners (TruffleHog, GitLeaks) and human
attackers alike after a filesystem or repo compromise.

Automated scanners validate structure, not content: a string that merely *looks* like a private
key fails their regex; a real, valid key with a suspicious comment does not. This module
generates a genuinely valid SSH keypair via the real `ssh-keygen` binary and sets its comment
field to a beacon URL pointing at a registered Ghost-Schema bait path.

A verified correction worth knowing: the naive approach of editing a PEM-wrapped key's text
directly (inserting a raw `# comment` line right after the BEGIN marker) does not work - it fails
to parse (`binascii.Error: Incorrect padding`) because OpenSSH's actual comment field lives inside
the key's own binary-encoded structure, not as free text in the PEM wrapper. The real, correct
mechanism is `ssh-keygen -c -C "<comment>"` on an already-valid key, which is what this module
does - verified end-to-end (the key still round-trips through `ssh-keygen -y`, and the comment
shows up in the extracted public key line).

Honest scope - what this does NOT do: requires `ssh-keygen` on PATH - a real OS-level dependency,
not a pip package, and there is no pure-Python fallback, because producing a key indistinguishable
from a genuinely `ssh-keygen`-generated one is the entire point of this trap. Does not verify the
planted key was ever actually placed anywhere (a filesystem, a git repo) - that is a deployment
step this module has no opinion on.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import ghost_schema
from .beacon import check_plant_hit, extract_plant_id_from_query  # noqa: F401 (re-exported)


@dataclass(frozen=True)
class SshKeyPlant:
    private_key_path: Path
    public_key_path: Path
    plant_id: str
    bait_path: str
    full_url: str


def generate_ssh_key_trap(
    listener_host: str,
    output_dir: str | Path,
    index: int = 0,
    seed: bytes | None = None,
    bait_path: str = "/api/export",
    key_name: str = "id_rsa_prod",
) -> SshKeyPlant:
    """Generates a real 2048-bit SSH keypair via `ssh-keygen`, writes it to `output_dir`, and
    sets its comment to a beacon URL pointing at a registered Ghost-Schema bait path. `bait_path`
    must already be registered. `seed` defaults to a fresh random value for real use; pass a
    fixed value for reproducible tests. Refuses to overwrite an existing key file at the target
    path."""
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        raise RuntimeError(
            "ssh-keygen not found on PATH - this module needs the real binary, not a Python "
            "crypto library (see the module docstring for why)"
        )
    if not ghost_schema.is_bait_path(bait_path):
        raise ValueError(
            f"{bait_path!r} is not a registered Ghost-Schema bait path - planting a key "
            "against it would point at a real, unprotected endpoint instead of a tripwire"
        )

    seed = seed if seed is not None else secrets.token_bytes(32)
    plant_id = "chk_" + hmac.new(seed, str(index).encode("ascii"), hashlib.sha256).hexdigest()[:16]
    full_url = f"https://{listener_host}{bait_path}?plant={plant_id}"

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    private_key_path = output_dir / key_name
    public_key_path = output_dir / f"{key_name}.pub"

    if private_key_path.exists():
        raise FileExistsError(
            f"{private_key_path} already exists - refusing to overwrite an existing key file"
        )

    subprocess.run(
        [
            ssh_keygen, "-t", "rsa", "-b", "2048",
            "-f", str(private_key_path), "-N", "", "-C", "placeholder", "-q",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [ssh_keygen, "-c", "-C", full_url, "-f", str(private_key_path)],
        check=True,
        capture_output=True,
    )
    private_key_path.chmod(0o600)

    return SshKeyPlant(
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        plant_id=plant_id,
        bait_path=bait_path,
        full_url=full_url,
    )
