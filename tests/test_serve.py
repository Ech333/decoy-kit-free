"""Real end-to-end tests for serve.py's build_app() - the Ghost-Schema receiver the SSH key
trap's beacon URL points at. Uses a real starlette.testclient.TestClient hitting real routes, not
mocks.

Skipped automatically if the [serve] extra (fastapi/uvicorn/starlette) isn't installed.
"""

import unittest

try:
    from starlette.testclient import TestClient

    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False

SEED_HEX = "aa" * 32


@unittest.skipUnless(_HAS_FASTAPI, "fastapi/starlette not installed - pip install 'decoy-kit-free[serve]'")
class BuildAppTests(unittest.TestCase):
    def setUp(self):
        from decoy_kit_free.serve import build_app

        self.hits = []
        self.app = build_app(seed_hex=SEED_HEX, siem_webhook=lambda name, detail: self.hits.append((name, detail)))
        self.client = TestClient(self.app)

    def test_ghost_schema_bait_path_returns_fake_payload_and_fires_the_webhook(self):
        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")
        self.assertEqual(self.hits[0][0], "ghost-schema")

    def test_non_bait_path_falls_through_to_a_real_404(self):
        resp = self.client.get("/this-path-does-not-exist")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.hits, [])

    def test_state_exposes_the_resolved_seed(self):
        self.assertEqual(self.app.state.seed, bytes.fromhex(SEED_HEX))


@unittest.skipUnless(_HAS_FASTAPI, "fastapi/starlette not installed - pip install 'decoy-kit-free[serve]'")
class ResolveSeedTests(unittest.TestCase):
    def test_explicit_seed_hex_is_used_verbatim(self):
        from decoy_kit_free.serve import _resolve_seed

        self.assertEqual(_resolve_seed(SEED_HEX), bytes.fromhex(SEED_HEX))

    def test_env_var_is_used_when_no_explicit_seed_is_given(self):
        import os

        from decoy_kit_free.serve import _resolve_seed

        os.environ["DECOY_KIT_FREE_SEED"] = SEED_HEX
        try:
            self.assertEqual(_resolve_seed(None), bytes.fromhex(SEED_HEX))
        finally:
            del os.environ["DECOY_KIT_FREE_SEED"]

    def test_no_seed_at_all_generates_a_fresh_unpredictable_one(self):
        import os

        from decoy_kit_free.serve import _resolve_seed

        os.environ.pop("DECOY_KIT_FREE_SEED", None)
        s1 = _resolve_seed(None)
        s2 = _resolve_seed(None)
        self.assertEqual(len(s1), 32)
        self.assertNotEqual(s1, s2)


if __name__ == "__main__":
    unittest.main()
