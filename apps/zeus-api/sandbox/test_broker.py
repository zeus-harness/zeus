import base64
import importlib.util
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('broker', pathlib.Path(__file__).with_name('broker.py'))
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

class BoundaryTests(unittest.TestCase):
    def test_paths_cannot_escape_or_import_git_metadata(self):
        for name in ('/etc/passwd', '../x', 'a/../x', '.git/config', 'a/.GIT/x', 'a//b', 'a\\b', 'a\0b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                broker.path_parts(name)
        self.assertEqual(broker.path_parts('src/main.rs'), ['src', 'main.rs'])

    def test_duplicate_files_and_non_boolean_modes_are_rejected(self):
        file = {'path': 'a', 'data': base64.b64encode(b'x').decode(), 'executable': False}
        with self.assertRaises(ValueError): broker.decode_files([file, file])
        with self.assertRaises(ValueError): broker.decode_files([{**file, 'executable': 'false'}])

    def test_symlinks_and_hardlinks_are_not_exported(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'a').write_text('original')
            (root / 'link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): broker.snapshot(root)
            (root / 'link').unlink()
            os.link(root / 'a', root / 'link')
            with self.assertRaises(ValueError): broker.snapshot(root)

    def test_image_tags_cannot_replace_a_digest(self):
        self.assertFalse(broker.valid_environment('alpine:latest'))
        self.assertTrue(broker.valid_environment('sha256:' + 'a' * 64))

if __name__ == '__main__': unittest.main()
