"""
Unit tests for SHA-256 Incremental Verification & Integrity Check.
Verifies that bounded-RAM streaming hash computation matches full-file SHA-256.
Run with:
    python -m unittest tests.test_sha256_verification -v
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from backend.uploader import compute_file_sha256


class TestSHA256Verification(unittest.TestCase):
    """
    Tests incremental SHA-256 calculation against ground-truth single-pass hashes.
    """

    def test_empty_file_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf_path = Path(tf.name)
        try:
            expected = hashlib.sha256(b"").hexdigest()
            actual = compute_file_sha256(tf_path)
            self.assertEqual(actual, expected)
        finally:
            tf_path.unlink(missing_ok=True)

    def test_small_file_hash(self):
        data = b"AI-SIEM Cyber Threat Detection Event Profiles"
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            tf_path = Path(tf.name)
        try:
            expected = hashlib.sha256(data).hexdigest()
            actual = compute_file_sha256(tf_path)
            self.assertEqual(actual, expected)
        finally:
            tf_path.unlink(missing_ok=True)

    def test_multi_megabyte_streaming_hash(self):
        # 3 MB deterministic stream across multiple 1MB chunk boundaries
        chunk = b"A" * (1024 * 1024)
        full_data = chunk + b"B" * (1024 * 1024) + b"C" * (512 * 1024)
        expected = hashlib.sha256(full_data).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(full_data)
            tf_path = Path(tf.name)
        try:
            actual = compute_file_sha256(tf_path, buffer_size=1024 * 1024)
            self.assertEqual(actual, expected)
        finally:
            tf_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
