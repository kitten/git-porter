import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("checker", Path(__file__).resolve().parents[2] / "scripts/check_llp_refs.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class References(unittest.TestCase):
    def test_nix_and_duplicate_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "llp").mkdir()
            (root / "llp/0000-policy.explainer.md").write_text("# Policy\n## Boundary\n## Boundary\n")
            (root / "policy.nix").write_text("# @" + "ref LLP 0000#boundary-1\n")
            old_root, old_llp = checker.ROOT, checker.LLP_DIR
            try:
                checker.ROOT, checker.LLP_DIR = root, root / "llp"
                self.assertIn(root / "policy.nix", checker.scan_files())
                self.assertIn("boundary-1", checker.load_llp_docs()["0000"][1])
                self.assertEqual(checker.main(), 0)
                (root / "policy.nix").write_text("# @" + "ref LLP 0000#missing\n")
                self.assertEqual(checker.main(), 1)
                (root / "policy.nix").write_text("# @" + "ref LLP 9999\n")
                self.assertEqual(checker.main(), 1)
                (root / "target").mkdir()
                (root / "target/generated.nix").write_text("# @" + "ref LLP 9999\n")
                self.assertNotIn(root / "target/generated.nix", checker.scan_files())
            finally:
                checker.ROOT, checker.LLP_DIR = old_root, old_llp


if __name__ == "__main__":
    unittest.main()
