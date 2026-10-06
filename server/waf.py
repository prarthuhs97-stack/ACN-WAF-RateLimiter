"""Stateless, thread-safe signature-based WAF. Inspects the *normalized* request only."""

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("waf")

# ---- Field aliases on the NormalizedRequest (edit here if your names differ) ----
PATH_ATTRS = ("path", "normalized_path")
QUERY_ATTRS = ("query", "normalized_query", "query_string")
PARAMS_ATTRS = ("params", "query_params", "form")
BODY_ATTRS = ("body", "body_text", "normalized_body")
FLAG_ATTRS = ("flags", "detections", "anomalies", "findings")
_LOCATIONS = (
    ("path", PATH_ATTRS),
    ("query", QUERY_ATTRS + PARAMS_ATTRS),
    ("body", BODY_ATTRS),
)

SQLI = "sql_injection"
XSS = "xss"
TRAVERSAL = "path_traversal"
EVASION = "encoding_evasion"


@dataclass(frozen=True)
class Rule:
    attack_type: str
    name: str
    pattern: "re.Pattern"


@dataclass(frozen=True)
class WafResult:
    blocked: bool
    attack_type: Optional[str] = None
    rule: Optional[str] = None
    location: Optional[str] = None

    @property
    def allowed(self):
        return not self.blocked


ALLOWED = WafResult(False)


def _r(attack_type, name, regex):
    return Rule(attack_type, name, re.compile(regex, re.IGNORECASE | re.DOTALL))


_WS = r"(?:\s|/\*[^*]*\*/)+"  # whitespace or inline /* comment */

DEFAULT_RULES = (
    # --- SQL injection ---
    _r(SQLI, "sqli_tautology_quote",
       r"['\"]\s*(?:or|and)(?:\s+|(?=['\"]))['\"]?\w+['\"]?\s*(?:=|<|>|like\b)"),
    _r(SQLI, "sqli_tautology_numeric", r"\b(?:or|and)\s+(\d+)\s*=\s*\1\b"),
    _r(SQLI, "sqli_union_select",
       r"\bunion" + _WS + r"(?:(?:all|distinct)" + _WS + r")?select\b"),
    _r(SQLI, "sqli_select_from",
       r"\bselect" + _WS + r"(?:\*|[\w.()*`]+(?:\s*,\s*[\w.()`]+)*)" + _WS
       + r"from" + _WS + r"[\w.`\[]+"),
    _r(SQLI, "sqli_ddl",
       r"\b(?:drop|truncate|alter)" + _WS + r"(?:table|database|schema|view|index)\b"),
    _r(SQLI, "sqli_dml",
       r"\bdelete" + _WS + r"from\b|\binsert" + _WS + r"into\b|\bupdate" + _WS
       + r"\w+" + _WS + r"set" + _WS + r"\w+\s*="),
    _r(SQLI, "sqli_stacked", r";\s*(?:drop|delete|insert|truncate|shutdown|exec|xp_)"),
    _r(SQLI, "sqli_comment_after_quote", r"['\"]\s*(?:--|/\*)|;\s*--"),
    _r(SQLI, "sqli_time_based",
       r"\b(?:sleep|pg_sleep|benchmark)\s*\(\s*\d|\bwaitfor" + _WS + r"delay\b"),
    _r(SQLI, "sqli_functions", r"\b(?:load_file|extractvalue|updatexml)\s*\("),
    _r(SQLI, "sqli_system_objects",
       r"\binformation_schema\b|\bxp_cmdshell\b|\bsysobjects\b|\bpg_catalog\b|@@version"
       r"|\binto" + _WS + r"(?:out|dump)file\b"),
    # --- XSS ---
    _r(XSS, "xss_script_tag", r"<\s*/?\s*script\b"),
    _r(XSS, "xss_script_uri", r"\b(?:javascript|vbscript)\s*:|data\s*:\s*text/html"),
    _r(XSS, "xss_event_handler",
       r"\bon(?:error|load|unload|click|dblclick|focus|blur|submit|change|input|toggle"
       r"|abort|begin|start|(?:mouse|key|pointer|animation|touch|drag)\w*)\s*="),
    _r(XSS, "xss_dangerous_tag",
       r"<\s*(?:iframe|object|embed|applet|meta|base|svg|style|link)\b"),
    _r(XSS, "xss_dom_js",
       r"\bdocument\.(?:cookie|write|domain|location)|\bwindow\.location|\beval\s*\("
       r"|\b(?:alert|prompt|confirm)\s*\(\s*(?:\d|['\"`]|document|window)"),
    # --- Path traversal (text left in values; path traversal is mainly via flags) ---
    _r(TRAVERSAL, "traversal_dotdot",
   r"(?:^|[^.\w])\.\.(?:[\\/]|$)|[\\/]\.\.(?:[\\/]|$)"),
    _r(TRAVERSAL, "traversal_sensitive_file",
       r"(?:^|[\\/])etc[\\/](?:passwd|shadow|group|hosts)\b|\b(?:boot|win)\.ini\b"
       r"|[\\/]windows[\\/]system32|/proc/self/"),
)

# normalization flag -> (attack_type, rule name)
DEFAULT_FLAG_RULES = {
    "traversal": (TRAVERSAL, "flag:traversal"),
    "null_byte": (TRAVERSAL, "flag:null_byte"),
    "double_encoding": (EVASION, "flag:double_encoding"),
}


def _texts(v):
    if v is None:
        return
    if isinstance(v, (bytes, bytearray)):
        yield bytes(v).decode("utf-8", "replace")
    elif isinstance(v, str):
        yield v
    elif isinstance(v, Mapping):
        for k, x in v.items():
            yield from _texts(k)
            yield from _texts(x)
    elif isinstance(v, (list, tuple, set, frozenset)):
        for x in v:
            yield from _texts(x)


class WAF:
    def __init__(self, rules=None, flag_rules=None):
        self._rules = tuple(DEFAULT_RULES if rules is None else rules)
        self._flag_rules = dict(DEFAULT_FLAG_RULES if flag_rules is None else flag_rules)

    def inspect(self, normalized):
        """Return WafResult. Never mutates `normalized`."""
        flags = self._flags(normalized)
        for flag, (attack, rule) in self._flag_rules.items():
            if flag in flags:
                return WafResult(True, attack, rule, "normalization")
        for location, text in self._targets(normalized):
            for rule in self._rules:
                if rule.pattern.search(text):
                    return WafResult(True, rule.attack_type, rule.name, location)
        return ALLOWED

    def _flags(self, n):
        out = set()
        for a in FLAG_ATTRS:
            v = getattr(n, a, None)
            if v is None:
                continue
            if isinstance(v, Mapping):
                out.update(str(k).lower() for k, x in v.items() if x)
            elif isinstance(v, (list, tuple, set, frozenset)):
                out.update(str(getattr(x, "name", x)).lower() for x in v)
            elif isinstance(v, str):
                out.add(v.lower())
        for name in self._flag_rules:
            if getattr(n, name, False) is True:
                out.add(name)
        return out

    @staticmethod
    def _targets(n):
        seen = set()
        for location, attrs in _LOCATIONS:
            for a in attrs:
                for t in _texts(getattr(n, a, None)):
                    if t and (location, t) not in seen:
                        seen.add((location, t))
                        yield location, t