"""Tests for the shared plant-id beacon helpers."""

import unittest

from decoy_kit_free.beacon import check_plant_hit, extract_plant_id_from_query


class ExtractPlantIdTests(unittest.TestCase):
    def test_extracts_plant_id_from_a_well_formed_url(self):
        url = "https://listener.example.com/api/export?plant=chk_abc123def456abcd"
        self.assertEqual(extract_plant_id_from_query(url), "chk_abc123def456abcd")

    def test_url_without_a_plant_param_extracts_nothing(self):
        self.assertIsNone(extract_plant_id_from_query("https://listener.example.com/api/export"))

    def test_malformed_plant_value_is_rejected(self):
        url = "https://listener.example.com/api/export?plant=not-a-real-plant-id"
        self.assertIsNone(extract_plant_id_from_query(url))


class CheckPlantHitTests(unittest.TestCase):
    def test_hit_on_a_planted_id_is_detected(self):
        url = "https://listener.example.com/api/export?plant=chk_abc123def456abcd"
        hit = check_plant_hit(url, {"chk_abc123def456abcd"})
        self.assertEqual(hit, "chk_abc123def456abcd")

    def test_well_formed_but_unplanted_id_is_not_a_hit(self):
        hit = check_plant_hit(
            "https://x.com/api/export?plant=chk_0000000000000000", {"chk_ffffffffffffffff"}
        )
        self.assertIsNone(hit)

    def test_url_with_no_plant_param_is_never_a_hit(self):
        hit = check_plant_hit("https://x.com/api/export", {"chk_0000000000000000"})
        self.assertIsNone(hit)


if __name__ == "__main__":
    unittest.main()
