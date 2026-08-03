"""Real subprocess tests for the decoy-kit-free CLI - shells out to `python -m
decoy_kit_free.cli`, doesn't call build_parser()/main() in-process, so a real argparse/entrypoint
wiring bug can't hide behind an in-process call that skips it."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "decoy_kit_free.cli", *args],
        capture_output=True, text=True, timeout=15,
    )


class HelpTests(unittest.TestCase):
    def test_top_level_help_lists_all_subcommands(self):
        result = _run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("generate", result.stdout)
        self.assertIn("serve", result.stdout)

    def test_no_command_is_a_usage_error_not_a_crash(self):
        result = _run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not on PATH in this environment")
class GenerateSshKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def test_writes_a_real_keypair(self):
        result = _run_cli(
            "generate", "ssh-key", "--host", "listener.example.com", "--out", self.tmpdir.name
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Private key:", result.stdout)
        self.assertTrue((Path(self.tmpdir.name) / "id_rsa_prod").exists())

    def test_seed_hex_makes_the_plant_id_reproducible(self):
        seed = "bb" * 32
        r1 = _run_cli("generate", "ssh-key", "--host", "x.example.com", "--out", self.tmpdir.name, "--seed-hex", seed)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        beacon_line = next(l for l in r1.stdout.splitlines() if l.startswith("Beacon URL:"))
        self.assertIn("plant=chk_", beacon_line)

    def test_refusing_to_overwrite_surfaces_as_a_clean_cli_error(self):
        _run_cli("generate", "ssh-key", "--host", "listener.example.com", "--out", self.tmpdir.name)
        result = _run_cli("generate", "ssh-key", "--host", "listener.example.com", "--out", self.tmpdir.name)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_rejects_an_unregistered_bait_path_with_a_clean_error(self):
        result = _run_cli(
            "generate", "ssh-key", "--host", "listener.example.com",
            "--out", self.tmpdir.name, "--bait-path", "/not-a-real-bait-path",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class ServeCommandTests(unittest.TestCase):
    def test_serve_help_does_not_crash_even_without_the_extra_installed(self):
        result = _run_cli("serve", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--port", result.stdout)


if __name__ == "__main__":
    unittest.main()
