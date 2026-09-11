"""Release source and registry identity checks; no publication or network."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("identity_registry", Path(__file__).with_name("prepare-registry.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class RegistryPreparationTests(unittest.TestCase):
    def test_registry_conversion_keeps_the_exact_version_and_feature_boundary(self):
        source = 'anp = { path = "../anp/rust", version = "=1.0.3", default-features = false }\n'
        rewritten, version = release.registry_manifest(source)
        self.assertEqual(version, "1.0.3")
        self.assertNotIn("path =", rewritten)
        self.assertIn('version = "=1.0.3"', rewritten)
        self.assertIn("default-features = false", rewritten)

    def test_floating_git_missing_and_duplicate_dependencies_fail_closed(self):
        for source in [
            'anp = { version = "^1.0.3" }',
            'anp = { version = "=1.0.3", git = "https://example.invalid/anp" }',
            '[dependencies]\n',
            'anp = { version = "=1.0.3" }\nanp = { version = "=1.0.3" }',
        ]:
            with self.assertRaises(ValueError):
                release.registry_manifest(source)

    def test_metadata_accepts_only_one_exact_registry_anp(self):
        package = {"name": "anp", "version": "1.0.3", "source": release.REGISTRY}
        release.verify_metadata({"packages": [package]}, "1.0.3")
        for packages in [[], [package, package], [dict(package, source=None)],
                         [dict(package, source="git+https://example.invalid/anp")],
                         [dict(package, version="1.0.2")]]:
            with self.assertRaises(ValueError):
                release.verify_metadata({"packages": packages}, "1.0.3")

    def test_existing_build_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(release.subprocess, "check_output") as run:
            with self.assertRaisesRegex(ValueError, "overwrite"):
                release.prepare(Path(temporary), Path(temporary))
            run.assert_not_called()

    def test_dirty_source_is_not_archived(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            release.subprocess, "check_output", return_value=b" M Cargo.toml",
        ) as run:
            with self.assertRaisesRegex(ValueError, "Commit tracked"):
                release.prepare(Path(temporary), Path(temporary) / "source")
            self.assertEqual(run.call_count, 1)

    def test_native_workflow_builds_and_audits_the_registry_copy(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/native-node-artifacts.yml").read_text()
        self.assertEqual(workflow.count("prepare-registry.py --prepare ../anp-identity-registry"), 2)
        self.assertEqual(workflow.count("working-directory: anp-identity-registry"), 2)
        self.assertIn("ANP_IDENTITY_REGISTRY_MANIFEST:", workflow)
        self.assertIn("RUSTUP_TOOLCHAIN: 1.88.0", workflow)
        stage = (root / "scripts/release/stage-node-package.mjs").read_text()
        self.assertIn("--manifest-path", stage)
        self.assertIn("registry+https://github.com/rust-lang/crates.io-index", stage)


if __name__ == "__main__":
    unittest.main()
