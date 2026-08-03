"""Tests for Ghost-Schema. Pure stdlib unittest - no FastAPI dependency needed for these."""

import unittest

from decoy_kit_free.ghost_schema import evaluate, is_bait_path, payload_json

SEED = b"test-seed-not-real"


class GhostSchemaTests(unittest.TestCase):
    def test_non_bait_path_returns_none(self):
        self.assertIsNone(evaluate("/products", "1.2.3.4", SEED))
        self.assertFalse(is_bait_path("/products"))

    def test_bait_path_returns_fake_payload(self):
        r = evaluate("/admin", "1.2.3.4", SEED)
        self.assertIsNotNone(r)
        self.assertEqual(r.payload["status"], "ok")
        self.assertTrue(is_bait_path("/admin"))

    def test_same_source_gets_consistent_fake_data_across_repeat_hits(self):
        r1 = evaluate("/admin", "1.2.3.4", SEED)
        r2 = evaluate("/admin", "1.2.3.4", SEED)
        self.assertEqual(r1.payload, r2.payload)
        self.assertEqual(r1.source_token, r2.source_token)

    def test_different_sources_get_different_fake_data(self):
        r1 = evaluate("/admin", "1.2.3.4", SEED)
        r2 = evaluate("/admin", "5.6.7.8", SEED)
        self.assertNotEqual(r1.source_token, r2.source_token)
        self.assertNotEqual(r1.payload, r2.payload)

    def test_different_seed_changes_token_for_same_source(self):
        r1 = evaluate("/admin", "1.2.3.4", SEED)
        r2 = evaluate("/admin", "1.2.3.4", b"a-different-seed")
        self.assertNotEqual(r1.source_token, r2.source_token)

    def test_token_never_reveals_the_seed(self):
        r = evaluate("/admin", "1.2.3.4", SEED)
        self.assertNotIn(SEED.decode(), r.source_token)

    def test_all_registered_bait_paths_produce_valid_json(self):
        for path in ["/admin", "/.env", "/backup", "/backup.sql", "/wp-admin", "/.git/config", "/api/export", "/phpmyadmin"]:
            r = evaluate(path, "9.9.9.9", SEED)
            self.assertIsNotNone(r, f"{path} should be a registered bait path")
            json_str = payload_json(r)
            self.assertIsInstance(json_str, str)
            self.assertGreater(len(json_str), 2)

    def test_nested_template_substitution(self):
        r = evaluate("/.git/config", "1.2.3.4", SEED)
        self.assertIn(r.source_token, r.payload["remote"]["origin"]["url"])

    def test_env_path_does_not_leak_the_real_seed_as_the_fake_secret(self):
        r = evaluate("/.env", "1.2.3.4", SEED)
        self.assertNotIn(SEED.decode(), r.payload["AWS_SECRET_ACCESS_KEY"])
        self.assertNotEqual(r.payload["AWS_SECRET_ACCESS_KEY"], "{n}")


if __name__ == "__main__":
    unittest.main()
