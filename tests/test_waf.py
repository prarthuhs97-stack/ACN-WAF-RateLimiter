import copy
import os
import re
import sys
import threading
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from waf import WAF, Rule, WafResult  # noqa: E402


def nr(path="/", query="", body="", flags=()):
    return SimpleNamespace(path=path, query=query, body=body, flags=set(flags))


class TestWAF(unittest.TestCase):
    def setUp(self):
        self.waf = WAF()

    def blocked(self, req, attack=None, location=None):
        r = self.waf.inspect(req)
        self.assertTrue(r.blocked, "expected block: %r" % (req,))
        if attack:
            self.assertEqual(r.attack_type, attack)
        if location:
            self.assertEqual(r.location, location)
        return r

    def allowed(self, req):
        r = self.waf.inspect(req)
        self.assertTrue(r.allowed, "unexpected block %s: %r" % (r, req))

    # ---- SQLi ----
    def test_sqli_obvious(self):
        for q in ["id=1' OR 1=1--", "id=1' or '1'='1", "id=1 OR 1=1", "id=1' AND 1=1",
                  "q=1 UNION SELECT username,password FROM users", "q=1 UNION ALL SELECT NULL",
                  "q=SELECT * FROM users", "q=SELECT name FROM users", "q=1; DROP TABLE users",
                  "q=admin'--", "q=1; DELETE FROM users", "q=INSERT INTO users VALUES (1)",
                  "q=UPDATE users SET admin=1", "id=1 AND SLEEP(5)",
                  "q=SELECT table_name FROM information_schema.tables",
                  "name=Robert'); DROP TABLE Students;--"]:
            with self.subTest(q=q):
                self.blocked(nr(query=q), attack="sql_injection", location="query")

    def test_sqli_in_body(self):
        self.blocked(nr(body="user=admin' OR '1'='1&pass=x"), "sql_injection", "body")

    def test_sqli_in_path(self):
        self.blocked(nr(path="/search/' OR 1=1--"), "sql_injection", "path")

    def test_sqli_decoded_whitespace_variants(self):
        # what the normalizer hands over after decoding %09, %0a, +, and /**/ tricks
        for q in ["q=1 UNION\tSELECT 1", "q=1 UNION\nSELECT 1", "q=1 UNION/**/SELECT 1",
                  "q=1 UNION   ALL   SELECT 1"]:
            with self.subTest(q=q):
                self.blocked(nr(query=q), "sql_injection")

    # ---- XSS ----
    def test_xss(self):
        for q in ["<script>alert(1)</script>", "<SCRIPT SRC=//evil.com/x.js></SCRIPT>",
                  "javascript:alert(1)", "vbscript:msgbox(1)", "<img src=x onerror=alert(1)>",
                  "<body onload=alert(1)>", "<a onclick=steal()>x</a>",
                  "<iframe src=//evil.com>", "<svg onload=alert(1)>", "<  script >",
                  "x=document.cookie", "onerror=alert(1)", "<div onmouseover=x()>"]:
            with self.subTest(q=q):
                self.blocked(nr(query="q=" + q), attack="xss", location="query")

    def test_xss_in_body_and_path(self):
        self.blocked(nr(body="comment=<script>alert(1)</script>"), "xss", "body")
        self.blocked(nr(path="/<script>alert(1)</script>"), "xss", "path")

    def test_case_variations(self):
        self.blocked(nr(query="q=<ScRiPt>alert(1)</sCrIpT>"), "xss")
        self.blocked(nr(query="q=JaVaScRiPt:alert(1)"), "xss")
        self.blocked(nr(query="q=OnErRoR=alert(1)"), "xss")
        self.blocked(nr(query="q=1 uNiOn SeLeCt 1"), "sql_injection")
        self.blocked(nr(query="q=dRoP tAbLe users"), "sql_injection")

    # ---- Traversal ----
    def test_traversal_text_in_values(self):
        for q in ["file=../../etc/passwd", "file=..\\..\\windows\\system32", "file=/etc/passwd",
                  "f=..\\boot.ini", "f=/var/www/../../etc/shadow", "f=..", "f=a/.."]:
            with self.subTest(q=q):
                self.blocked(nr(query=q), attack="path_traversal")

    def test_traversal_flags(self):
        self.blocked(nr(flags={"traversal"}), "path_traversal")
        self.blocked(nr(flags={"null_byte"}), "path_traversal")
        self.blocked(nr(flags={"double_encoding"}), "encoding_evasion")
        self.blocked(nr(flags={"TRAVERSAL"}), "path_traversal")
        self.blocked(SimpleNamespace(path="/", query="", body="", flags=["traversal"]))
        self.blocked(SimpleNamespace(path="/", query="", body="", flags={"traversal": True}))
        self.blocked(SimpleNamespace(path="/", query="", body="", traversal=True))
        r = self.blocked(nr(flags={"traversal"}))
        self.assertEqual(r.rule, "flag:traversal")

    def test_non_blocking_flags(self):
        self.allowed(nr(flags={"backslash"}))
        self.allowed(nr(flags={"invalid_encoding"}))
        self.allowed(SimpleNamespace(path="/", query="", body="", flags={"traversal": False}))

    # ---- Benign ----
    def test_benign_paths(self):
        for p in ["/", "/index.html", "/images/logo.png", "/api/v1/users/42", "/about-us",
                  "/blog/2024/10/my-first-post", "/a.b/c..d/e", "/files/report..final.pdf"]:
            with self.subTest(p=p):
                self.allowed(nr(path=p))

    def test_benign_query(self):
        for q in ["name=John Smith", "q=hello world", "page=2&sort=asc", "email=user@example.com",
                  "redirect=https://example.com/path", "q=rock & roll", "name=O'Brien",
                  "q=select a plan from the list", "msg=Tom's or Jerry's", "q=drop by the table",
                  "q=union station", "q=100% sure", "q=a--b", "q=C++ & C#", "q=the onload event",
                  "q=javascript tutorial", "q=hello; world", "q=1=1", "q=Please update your settings",
                  "q=Tom's cat or dog", "q=rock and roll = fun", "q=version 2..3"]:
            with self.subTest(q=q):
                self.allowed(nr(query=q))

    def test_benign_body(self):
        for b in ["username=alice&password=Secr3t!pass",
                  "comment=Great post! I loved the part about sleep and rest.",
                  "message=Hello,\nThis is a multi-line\nmessage.",
                  '{"name": "Alice", "age": 30, "note": "it\'s fine"}',
                  "title=Selecting the best option",
                  "bio=I work for Union Bank and select clients",
                  "text=Prices: $5 - $10, 50% off!", "a=1&b=2&c=3"]:
            with self.subTest(b=b):
                self.allowed(nr(body=b))

    # ---- Misc behavior ----
    def test_multiple_attack_types(self):
        r = self.blocked(nr(body="x=<script>alert(1)</script>&y=' OR 1=1--"))
        self.assertIn(r.attack_type, ("sql_injection", "xss"))
        r = self.blocked(nr(query="id=1' OR 1=1--", flags={"traversal"}))
        self.assertEqual(r.attack_type, "path_traversal")  # flags checked first

    def test_location_reporting(self):
        self.blocked(nr(path="/<script>"), location="path")
        self.blocked(nr(query="q=<script>"), location="query")
        self.blocked(nr(body="q=<script>"), location="body")

    def test_result_structure(self):
        a = self.waf.inspect(nr())
        self.assertIsInstance(a, WafResult)
        self.assertTrue(a.allowed)
        self.assertFalse(a.blocked)
        self.assertIsNone(a.attack_type)
        self.assertIsNone(a.rule)
        self.assertIsNone(a.location)
        b = self.waf.inspect(nr(query="q=<script>"))
        self.assertTrue(b.blocked)
        self.assertFalse(b.allowed)
        self.assertEqual((b.attack_type, b.rule, b.location), ("xss", "xss_script_tag", "query"))
        with self.assertRaises(AttributeError):
            b.blocked = False

    def test_request_not_modified(self):
        req = nr(path="/a", query="q=' OR 1=1--", body="<script>", flags={"traversal"})
        before = copy.deepcopy(req)
        self.waf.inspect(req)
        self.assertEqual(req, before)

    def test_input_shapes(self):
        self.blocked(nr(query={"q": ["' OR 1=1--"]}), "sql_injection")
        self.blocked(nr(query=[("q", "<script>")]), "xss")
        self.blocked(nr(body=b"<script>alert(1)</script>"), "xss", "body")
        self.allowed(nr(body=b"\xff\xfe plain"))
        self.allowed(SimpleNamespace())
        self.allowed(SimpleNamespace(path=None, query=None, body=None, flags=None))

    def test_custom_rules(self):
        waf = WAF(rules=[Rule("custom", "no_foo", re.compile("foo"))])
        r = waf.inspect(nr(query="q=foo"))
        self.assertEqual((r.attack_type, r.rule), ("custom", "no_foo"))
        self.assertTrue(waf.inspect(nr(query="q=' OR 1=1--")).allowed)

    def test_thread_safety(self):
        cases = [(nr(query="id=1' OR 1=1--"), True), (nr(query="name=John"), False),
                 (nr(body="<script>"), True), (nr(path="/index.html"), False)]
        errors = []

        def worker():
            for _ in range(200):
                for req, exp in cases:
                    if self.waf.inspect(req).blocked != exp:
                        errors.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(errors, [])

    def test_pathological_input_is_fast(self):
        start = time.monotonic()
        for payload in ["/*" * 5000, "select " * 3000, "union " * 3000, "'" * 5000,
                        "a" * 50000, "or " * 5000]:
            self.waf.inspect(nr(query=payload, body=payload))
        self.assertLess(time.monotonic() - start, 5.0)


if __name__ == "__main__":
    unittest.main()