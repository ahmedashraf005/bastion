"""Profile resolution must never silently mix demo and default policy files."""

from pathlib import Path
import unittest

from app.policy_profile import GATE_ROOT, active_manifest_version, resolve_policy_profile


class PolicyProfileTests(unittest.TestCase):
    def test_default_paths_are_the_existing_live_paths(self) -> None:
        profile = resolve_policy_profile(None)
        self.assertEqual(profile.name, "default")
        self.assertEqual(profile.rules, GATE_ROOT / "policy" / "rules.yaml")
        self.assertEqual(profile.leak_patterns, GATE_ROOT / "detectors" / "leak_patterns.yaml")

    def test_demo_profile_resolves_all_detector_files_together(self) -> None:
        profile = resolve_policy_profile("demo-permissive")
        self.assertEqual(profile.name, "demo-permissive")
        for path in (
            profile.rules,
            profile.leak_patterns,
            profile.normalization_versions,
            profile.pattern_versions,
        ):
            self.assertTrue(path.is_file(), path)
        self.assertIsNone(active_manifest_version(profile.normalization_versions))
        self.assertEqual(
            active_manifest_version(profile.pattern_versions),
            "marker-ref-demo-permissive-v1",
        )

    def test_incomplete_or_unsafe_profile_fails_fast(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "invalid Gate policy profile"):
            resolve_policy_profile("../default")
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            resolve_policy_profile("missing-profile")

    def test_rules_override_cannot_be_combined_with_profile(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "cannot be combined"):
            resolve_policy_profile("demo-permissive", Path("/tmp/rules.yaml"))
