# Check objective: Verify atomic no-replace publication on the current operating system.
import importlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
files = importlib.import_module("installer_files")


class PublicationTests(unittest.TestCase):
    def test_publish_then_refuse_existing_empty_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            source, destination = parent / "source", parent / "destination"
            source.mkdir(mode=0o700)
            (source / "content").write_text("non-secret")
            files.publish_directory(source, destination)
            self.assertFalse(source.exists())
            self.assertEqual((destination / "content").read_text(), "non-secret")
            source.mkdir(mode=0o700)
            inode = source.stat().st_ino
            with self.assertRaises(FileExistsError):
                files.publish_directory(destination, source)
            self.assertEqual(source.stat().st_ino, inode)
            self.assertEqual(list(source.iterdir()), [])

    def test_unsupported_platform_does_not_fall_back_to_rename(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve() / "source"
            destination = source.parent / "destination"
            source.mkdir()
            with patch.object(files.sys, "platform", "unsupported"), self.assertRaises(OSError):
                files.publish_directory(source, destination)
            self.assertTrue(source.is_dir())
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
