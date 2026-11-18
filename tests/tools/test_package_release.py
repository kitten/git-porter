"""Release archive and manifest contracts, using synthetic files only."""
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "package_release", Path(__file__).resolve().parents[2] / "scripts/package_release.py"
)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class PackagingTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "package"
        for name in ("bin/git-porter", "bin/git-send", "bin/git-receive",
                     "share/doc/git-porter/LICENSE", "share/doc/git-porter/README.md"):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic input")
        return source

    def test_deterministic_allowlisted_archive_and_overwrite_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            a = release.package(source, root / "a", "aarch64-darwin", "0.1.0")
            b = release.package(source, root / "b", "aarch64-darwin", "0.1.0")
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with tarfile.open(a) as archive:
                entries = archive.getmembers()
                self.assertEqual(
                    sorted(Path(e.name).name for e in entries),
                    ["LICENSE", "README.md", "git-porter", "git-receive", "git-send"],
                )
                for entry in entries:
                    self.assertEqual((entry.uid, entry.gid, entry.mtime), (0, 0, 0))
                    self.assertEqual(entry.mode, 0o755 if Path(entry.name).name.startswith("git-") else 0o644)
            with self.assertRaises(FileExistsError):
                release.package(source, root / "a", "aarch64-darwin", "0.1.0")
            (source / "bin/extra").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                release.package(source, root / "c", "aarch64-darwin", "0.1.0")

    def test_complete_manifest_checks_actual_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            dist = root / "dist"
            for system in release.TARGETS:
                release.package(source, dist, system, "0.1.0")
            release.manifest(dist, "0.1.0")
            self.assertEqual(len((dist / "SHA256SUMS").read_text().splitlines()), 3)
            path = dist / release.filename("0.1.0", "aarch64-linux")
            path.write_bytes(path.read_bytes() + b"bad")
            with self.assertRaises(ValueError):
                release.manifest(dist, "0.1.0")

    def test_version_matches_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('[package]\nversion = "0.1.0"\n')
            self.assertEqual(release.version("v0.1.0", root), "0.1.0")
            with self.assertRaises(ValueError):
                release.version("v0.2.0", root)
