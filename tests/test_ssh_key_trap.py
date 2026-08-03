"""Tests for the SSH key secret-scanner trap. Deliberately real, not mocked: this module's
entire value proposition is producing a key indistinguishable from a genuine ssh-keygen output,
so these tests shell out to the real ssh-keygen binary to prove it. Skipped automatically if
ssh-keygen isn't on PATH rather than failing for an unrelated environment reason.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from decoy_kit_free import ghost_schema
from decoy_kit_free.ssh_key_trap import check_plant_hit, generate_ssh_key_trap

SEED = b"fixed-test-seed"

_HAS_SSH_KEYGEN = shutil.which("ssh-keygen") is not None


@unittest.skipUnless(_HAS_SSH_KEYGEN, "ssh-keygen not on PATH in this environment")
class GenerateSshKeyTrapTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def test_produces_a_real_key_that_round_trips_through_ssh_keygen(self):
        plant = generate_ssh_key_trap("listener.example.com", self.tmpdir.name, seed=SEED)
        self.assertTrue(plant.private_key_path.exists())

        result = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(plant.private_key_path)],
            check=True, capture_output=True, text=True,
        )
        self.assertTrue(result.stdout.startswith("ssh-rsa "))

    def test_beacon_url_is_embedded_in_the_comment_and_survives_round_trip(self):
        plant = generate_ssh_key_trap("listener.example.com", self.tmpdir.name, seed=SEED)
        result = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(plant.private_key_path)],
            check=True, capture_output=True, text=True,
        )
        self.assertIn(plant.full_url, result.stdout)

    def test_default_bait_path_is_a_real_registered_ghost_schema_path(self):
        plant = generate_ssh_key_trap("listener.example.com", self.tmpdir.name, seed=SEED)
        self.assertTrue(ghost_schema.is_bait_path(plant.bait_path))

    def test_unregistered_bait_path_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_ssh_key_trap(
                "listener.example.com", self.tmpdir.name, bait_path="/not-a-real-bait-path"
            )

    def test_refuses_to_overwrite_an_existing_key(self):
        generate_ssh_key_trap("listener.example.com", self.tmpdir.name, seed=SEED)
        with self.assertRaises(FileExistsError):
            generate_ssh_key_trap("listener.example.com", self.tmpdir.name, seed=SEED)

    def test_private_key_file_is_written_with_owner_only_permissions(self):
        plant = generate_ssh_key_trap("listener.example.com", self.tmpdir.name, seed=SEED)
        mode = plant.private_key_path.stat().st_mode & 0o777
        if os.name == "posix":
            self.assertEqual(mode, 0o600)

    def test_plant_id_has_the_expected_prefix_and_is_embedded_in_the_beacon_url(self):
        plant = generate_ssh_key_trap("listener.example.com", self.tmpdir.name, seed=SEED)
        self.assertTrue(plant.plant_id.startswith("chk_"))
        self.assertIn(f"plant={plant.plant_id}", plant.full_url)

    def test_hit_on_a_planted_key_is_detected_by_the_re_exported_checker(self):
        plant = generate_ssh_key_trap("listener.example.com", self.tmpdir.name, seed=SEED)
        hit = check_plant_hit(plant.full_url, {plant.plant_id})
        self.assertEqual(hit, plant.plant_id)


if __name__ == "__main__":
    unittest.main()
