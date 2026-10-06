import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from http_parser import ParseError, get_content_length, parse_request_head


class TestParseRequestHead(unittest.TestCase):
    def assert_error(self, head, status):
        with self.assertRaises(ParseError) as ctx:
            parse_request_head(head)
        self.assertEqual(ctx.exception.status, status)

    def test_simple_get(self):
        req = parse_request_head(b"GET /hello HTTP/1.1\r\nHost: localhost:8080")
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.path, "/hello")
        self.assertEqual(req.query, "")
        self.assertEqual(req.version, "HTTP/1.1")
        self.assertEqual(req.headers["host"], "localhost:8080")

    def test_query_is_split_from_path(self):
        req = parse_request_head(b"GET /search?q=a&b=2 HTTP/1.1\r\nHost: x")
        self.assertEqual(req.path, "/search")
        self.assertEqual(req.query, "q=a&b=2")

    def test_path_and_query_are_not_decoded(self):
        req = parse_request_head(b"GET /a%20b?q=%3Cscript%3E HTTP/1.1\r\nHost: x")
        self.assertEqual(req.path, "/a%20b")
        self.assertEqual(req.query, "q=%3Cscript%3E")

    def test_header_names_lowercased_and_values_stripped(self):
        req = parse_request_head(b"GET / HTTP/1.1\r\nHost:   example.com  \r\nX-Test: A")
        self.assertEqual(req.headers["host"], "example.com")
        self.assertEqual(req.headers["x-test"], "A")

    def test_duplicate_headers_are_joined(self):
        req = parse_request_head(b"GET / HTTP/1.1\r\nHost: x\r\nAccept: a\r\nAccept: b")
        self.assertEqual(req.headers["accept"], "a, b")

    def test_http_10_does_not_need_host(self):
        req = parse_request_head(b"GET / HTTP/1.0")
        self.assertEqual(req.version, "HTTP/1.0")

    def test_bad_request_line(self):
        self.assert_error(b"GARBAGE\r\nHost: x", 400)

    def test_unsupported_method(self):
        self.assert_error(b"DELETE / HTTP/1.1\r\nHost: x", 501)

    def test_unsupported_version(self):
        self.assert_error(b"GET / HTTP/2.0\r\nHost: x", 505)

    def test_not_http_at_all(self):
        self.assert_error(b"GET / FTP/1.1\r\nHost: x", 400)

    def test_target_must_start_with_slash(self):
        self.assert_error(b"GET hello HTTP/1.1\r\nHost: x", 400)

    def test_header_without_colon(self):
        self.assert_error(b"GET / HTTP/1.1\r\nHost: x\r\nBrokenHeader", 400)

    def test_space_before_colon_in_header_name(self):
        self.assert_error(b"GET / HTTP/1.1\r\nHost : x", 400)

    def test_missing_host_in_http11(self):
        self.assert_error(b"GET / HTTP/1.1\r\nUser-Agent: x", 400)

    def test_chunked_not_supported(self):
        self.assert_error(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked", 501)


class TestContentLength(unittest.TestCase):
    def test_missing_means_zero(self):
        self.assertEqual(get_content_length({}), 0)

    def test_valid(self):
        self.assertEqual(get_content_length({"content-length": "42"}), 42)

    def test_not_a_number(self):
        with self.assertRaises(ParseError) as ctx:
            get_content_length({"content-length": "abc"})
        self.assertEqual(ctx.exception.status, 400)

    def test_too_large(self):
        with self.assertRaises(ParseError) as ctx:
            get_content_length({"content-length": "99999999"})
        self.assertEqual(ctx.exception.status, 413)


if __name__ == "__main__":
    unittest.main()