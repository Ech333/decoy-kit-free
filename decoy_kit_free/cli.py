"""Decoy Kit Free CLI.

`generate ssh-key` - a real SSH key with a beacon comment (writes files, needs ssh-keygen).
`serve`            - runs the Ghost-Schema receiver (needs the [serve] extra installed).
"""

from __future__ import annotations

import argparse
import sys


def _seed_bytes(seed_hex: str | None) -> bytes | None:
    return bytes.fromhex(seed_hex) if seed_hex else None


def _cmd_generate_ssh_key(args: argparse.Namespace) -> int:
    from .ssh_key_trap import generate_ssh_key_trap

    try:
        plant = generate_ssh_key_trap(
            args.host, args.out, seed=_seed_bytes(args.seed_hex), bait_path=args.bait_path
        )
    except (RuntimeError, ValueError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Private key: {plant.private_key_path}")
    print(f"Plant id:    {plant.plant_id}")
    print(f"Beacon URL:  {plant.full_url}")
    print()
    print("Plant the private key file somewhere an attacker who compromises this host or repo")
    print("would find it (e.g. ~/.ssh/, a CI secret store). Run 'decoy-kit-free serve' pointed")
    print("at --host above so the beacon URL actually resolves to something.")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print(
            "error: 'serve' needs the [serve] extra - pip install 'decoy-kit-free[serve]'",
            file=sys.stderr,
        )
        return 1
    from .serve import build_app

    # Real crash found live 2026-08-31 (found first in decoy-kit, ported here), sysadmin-
    # perspective stress test: build_app's first real step is resolving --seed-hex, and a
    # malformed one crashed with a raw ValueError traceback instead of a clean error - confirmed
    # live, identical bug to decoy-kit's own `serve` command.
    try:
        app = build_app(seed_hex=args.seed_hex)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    uvicorn.run(app, host=args.bind, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decoy-kit-free",
        description="A free honeytoken SSH key trap - the one piece of Decoy Kit given away in "
                     "full. Self-hosted, same as the paid product: you run the receiver, you "
                     "plant the key.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="generate a plantable decoy artifact")
    gen_sub = gen.add_subparsers(dest="artifact", required=True)

    p_ssh = gen_sub.add_parser("ssh-key", help="a real SSH key with a beacon comment")
    p_ssh.add_argument("--host", required=True, help="the hostname your 'serve' command runs on")
    p_ssh.add_argument("--out", required=True, help="directory to write the keypair into")
    p_ssh.add_argument("--bait-path", default="/api/export")
    p_ssh.add_argument("--seed-hex", default=None, help="hex-encoded seed (default: random)")
    p_ssh.set_defaults(func=_cmd_generate_ssh_key)

    p_serve = sub.add_parser("serve", help="run the Ghost-Schema receiver that catches the beacon")
    p_serve.add_argument("--bind", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--seed-hex", default=None, help="reuse a seed across restarts (or set DECOY_KIT_FREE_SEED)")
    p_serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
