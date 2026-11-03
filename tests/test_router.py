import base64
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import router  # noqa: E402


def fake_key_blob(seed: bytes = b"gl-mt3000-host-key") -> bytes:
    return hashlib.sha256(seed).digest()


class FingerprintTests(unittest.TestCase):
    def test_md5_hex_matches(self):
        blob = fake_key_blob()
        md5 = hashlib.md5(blob).hexdigest()
        self.assertTrue(router.key_fingerprint_matches(md5, blob))

    def test_md5_colon_matches_and_case_insensitive(self):
        blob = fake_key_blob(b"other")
        md5 = hashlib.md5(blob).hexdigest()
        colon = ":".join(md5[i:i + 2] for i in range(0, 32, 2)).upper()
        self.assertTrue(router.key_fingerprint_matches(colon, blob))

    def test_sha256_matches_with_and_without_padding(self):
        blob = fake_key_blob(b"sha")
        b64 = base64.b64encode(hashlib.sha256(blob).digest()).decode()
        self.assertTrue(router.key_fingerprint_matches("SHA256:" + b64, blob))
        self.assertTrue(
            router.key_fingerprint_matches("SHA256:" + b64.rstrip("="), blob))

    def test_wrong_fingerprint_rejected(self):
        blob = fake_key_blob()
        wrong = hashlib.md5(fake_key_blob(b"evil")).hexdigest()
        self.assertFalse(router.key_fingerprint_matches(wrong, blob))

    def test_invalid_fingerprints_rejected(self):
        blob = fake_key_blob()
        for bad in ["", "  ", "zzz", "abcdef", "SHA256:", "SHA256:!!!!",
                    "1e305652a871e9d0a1ea9d9c44711b1", None]:
            self.assertFalse(router.key_fingerprint_matches(bad, blob), bad)

    def test_empty_blob_rejected(self):
        self.assertFalse(router.key_fingerprint_matches("a" * 32, b""))


class PathTests(unittest.TestCase):
    def test_absolute_path_accepted_and_normalized(self):
        self.assertEqual(router.validate_remote_path("/tmp/./x"), "/tmp/x")
        self.assertEqual(router.validate_remote_path("/etc/netquota/a.db"),
                         "/etc/netquota/a.db")

    def test_relative_rejected(self):
        for bad in ["etc/config", "", "x"]:
            with self.assertRaises(router.CliError):
                router.validate_remote_path(bad)

    def test_traversal_rejected(self):
        for bad in ["/tmp/../../etc/passwd", "/..", "/tmp/.."]:
            with self.assertRaises(router.CliError):
                router.validate_remote_path(bad)

    def test_root_rejected(self):
        with self.assertRaises(router.CliError):
            router.validate_remote_path("/")

    def test_control_chars_rejected(self):
        for bad in ["/tmp/a\nb", "/tmp/a\rb", "/tmp/a\x00b", "/tmp/a\tb",
                    "/tmp/a\x7fb"]:
            with self.assertRaises(router.CliError):
                router.validate_remote_path(bad)


class QuoteTests(unittest.TestCase):
    def test_spaces_quoted(self):
        self.assertEqual(router.q("/tmp/my file.ipk"), "'/tmp/my file.ipk'")

    def test_single_quote_escaped(self):
        out = router.q("/tmp/it's.ipk")
        self.assertNotIn("''", out[1:-1].replace("'\\''", ""))
        self.assertIn("it", out)

    def test_shell_join_all_quoted(self):
        joined = router.shell_join(["/a b", "/c"])
        self.assertEqual(joined, "'/a b' /c")

    def test_quote_rejects_injection_path(self):
        with self.assertRaises(router.CliError):
            router.q("/tmp/x; rm -rf /\n")


class ScriptTests(unittest.TestCase):
    def test_crlf_normalized(self):
        self.assertEqual(router.normalize_script("a\r\nb\r\n"), "a\nb\n")

    def test_lone_cr_normalized(self):
        self.assertEqual(router.normalize_script("a\rb"), "a\nb\n")

    def test_trailing_newline_added(self):
        self.assertEqual(router.normalize_script("echo hi"), "echo hi\n")

    def test_existing_newline_preserved(self):
        self.assertEqual(router.normalize_script("echo hi\n"), "echo hi\n")


class TempNameTests(unittest.TestCase):
    def test_same_directory_unique(self):
        a = router.temp_name("/tmp/foo", ".netquota-upload.")
        b = router.temp_name("/tmp/foo", ".netquota-upload.")
        self.assertEqual(os.path.dirname(a), "/tmp/foo")
        self.assertNotEqual(a, b)


class ParserTests(unittest.TestCase):
    def test_defaults(self):
        args = router.build_parser().parse_args(["preflight"])
        self.assertEqual(args.host, router.DEFAULT_HOST)
        self.assertEqual(args.user, "root")
        self.assertEqual(args.port, 22)
        self.assertIsNone(args.fingerprint)

    def test_upload_args(self):
        args = router.build_parser().parse_args(
            ["upload", "x.ipk", "/tmp/x.ipk", "--mode", "600"])
        self.assertEqual(args.mode, "600")


if __name__ == "__main__":
    unittest.main()
