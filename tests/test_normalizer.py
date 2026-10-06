import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from http_parser import Request
from normalizer import normalize_request


def make(path, query="", headers=None, body=b""):
    return Request("GET", path, query, "HTTP/1.1", headers or {}, body)


class TestNormalizePath(unittest.TestCase):
    def test_plain_path_unchanged(self):
        n = normalize_request(make("/hello"))
        self.assertEqual(n.path, "/hello")
        self.assertEqual(n.flags, [])

    def test_percent_encoded_space(self):
        self.assertEqual(normalize_request(make("/a%20b")).path, "/a b")

    def test_plus_stays_plus_in_path(self):
        self.assertEqual(normalize_request(make("/a+b")).path, "/a+b")

    def test_trailing_slash_preserved(self):
        self.assertEqual(normalize_request(make("/a/b/")).path, "/a/b/")
        self.assertEqual(normalize_request(make("/")).path, "/")

    def test_repeated_slashes_and_dot_segments_collapsed(self):
        n = normalize_request(make("/a/./b//c"))
        self.assertEqual(n.path, "/a/b/c")
        self.assertEqual(n.flags, [])

    def test_dot_dot_resolved_and_flagged(self):
        n = normalize_request(make("/a/b/../c"))
        self.assertEqual(n.path, "/a/c")
        self.assertIn("traversal", n.flags)

    def test_traversal_above_root(self):
        n = normalize_request(make("/../../etc/passwd"))
        self.assertEqual(n.path, "/etc/passwd")
        self.assertIn("traversal", n.flags)

    def test_encoded_traversal(self):
        n = normalize_request(make("/%2e%2e/%2e%2e/etc/passwd"))
        self.assertEqual(n.path, "/etc/passwd")
        self.assertIn("traversal", n.flags)

    def test_encoded_traversal_uppercase_and_encoded_slash(self):
        n = normalize_request(make("/%2E%2E%2Fetc"))
        self.assertEqual(n.path, "/etc")
        self.assertIn("traversal", n.flags)

    def test_double_encoding_decoded_once_and_flagged(self):
        n = normalize_request(make("/%252e%252e/etc"))
        self.assertEqual(n.path, "/%2e%2e/etc")
        self.assertEqual(n.flags, ["double_encoding"])

    def test_backslash_treated_as_separator(self):
        n = normalize_request(make("/a%5c..%5cetc"))
        self.assertEqual(n.path, "/etc")
        self.assertIn("backslash", n.flags)
        self.assertIn("traversal", n.flags)

    def test_null_byte_flagged(self):
        n = normalize_request(make("/f%00.txt"))
        self.assertEqual(n.path, "/f\x00.txt")
        self.assertIn("null_byte", n.flags)

    def test_invalid_utf8_flagged(self):
        n = normalize_request(make("/%ff"))
        self.assertIn("invalid_encoding", n.flags)


class TestNormalizeQueryAndBody(unittest.TestCase):
    def test_query_decoded_and_params(self):
        n = normalize_request(make("/s", "q=%3Cscript%3E"))
        self.assertEqual(n.query, "q=<script>")
        self.assertEqual(n.params, [("q", "<script>")])
        self.assertEqual(n.flags, [])

    def test_plus_is_space_in_query(self):
        n = normalize_request(make("/s", "q=a+b"))
        self.assertEqual(n.params, [("q", "a b")])

    def test_encoded_plus_in_query(self):
        n = normalize_request(make("/s", "q=a%2Bb"))
        self.assertEqual(n.params, [("q", "a+b")])

    def test_empty_query(self):
        n = normalize_request(make("/s"))
        self.assertEqual(n.query, "")
        self.assertEqual(n.params, [])

    def test_param_without_value_and_empty_parts(self):
        n = normalize_request(make("/s", "flag&a=1&&b=2"))
        self.assertEqual(n.params, [("flag", ""), ("a", "1"), ("b", "2")])

    def test_form_body_decoded(self):
        headers = {"content-type": "application/x-www-form-urlencoded"}
        n = normalize_request(make("/login", headers=headers, body=b"user=%27+OR+1%3D1--"))
        self.assertEqual(n.body_text, "user=' OR 1=1--")

    def test_non_form_body_not_decoded(self):
        n = normalize_request(make("/x", body=b"a%20b"))
        self.assertEqual(n.body_text, "a%20b")


class TestOriginalPreserved(unittest.TestCase):
    def test_original_request_unchanged(self):
        req = make("/a%20b/../c", "q=%3C")
        before = copy.deepcopy(req)
        n = normalize_request(req)
        self.assertEqual(req, before)
        self.assertIs(n.original, req)


if __name__ == "__main__":
    unittest.main()