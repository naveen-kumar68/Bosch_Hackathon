import unittest

from guardian_policy import decide, reasons


def f(priority, confidence, type_, flags=None):
    return {"priority": priority, "confidence": confidence, "type": type_, "flags": flags or {}}


class PolicyTests(unittest.TestCase):
    def test_p0_needs_human(self):
        self.assertEqual(decide(f("P0", 0.9, "vulnerability")), "needs_human")

    def test_integrity_blocks(self):
        self.assertEqual(decide(f("P0", 0.9, "integrity_mismatch")), "block_candidate")

    def test_malicious_blocks(self):
        self.assertEqual(
            decide(f("P1", 0.9, "suspicious_change", {"ai_verdict": "malicious"})),
            "block_candidate",
        )

    def test_low_confidence_needs_human(self):
        self.assertEqual(decide(f("P2", 0.5, "vulnerability")), "needs_human")

    def test_ai_only_needs_human(self):
        self.assertEqual(
            decide(f("P3", 0.9, "suspicious_change", {"ai_only": True})), "needs_human"
        )

    def test_p3_high_confidence_auto(self):
        self.assertEqual(decide(f("P3", 0.85, "hygiene")), "auto_ok")

    def test_p2_default_needs_human(self):
        self.assertEqual(decide(f("P2", 0.9, "hygiene")), "needs_human")

    def test_p3_exactly_0_8_is_auto(self):
        self.assertEqual(decide(f("P3", 0.8, "hygiene")), "auto_ok")

    def test_p3_just_below_0_8_needs_human(self):
        self.assertEqual(decide(f("P3", 0.79, "hygiene")), "needs_human")

    def test_missing_flags_does_not_crash(self):
        self.assertEqual(decide({"priority": "P3", "confidence": 0.9, "type": "hygiene"}), "auto_ok")

    def test_reasons_listed(self):
        r = reasons(f("P0", 0.5, "integrity_mismatch"))
        self.assertIn("P0 priority", r)
        self.assertIn("confidence below 0.7", r)
        self.assertIn("integrity mismatch (same version, different contents)", r)


if __name__ == "__main__":
    unittest.main()