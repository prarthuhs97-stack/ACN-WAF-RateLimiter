import re
from dataclasses import dataclass
from urllib.parse import unquote

from http_parser import Request

PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")


@dataclass
class NormalizedRequest:
    original: Request
    path: str
    query: str
    params: list
    body_text: str
    headers: dict
    flags: list


def decode_once(text, plus=False):
    """Percent-decode exactly once. Returns (decoded_text, set_of_flags)."""
    flags = set()
    if plus:
        text = text.replace("+", " ")
    try:
        decoded = unquote(text, errors="strict")
    except UnicodeDecodeError:
        decoded = unquote(text, errors="replace")
        flags.add("invalid_encoding")
    if PERCENT_RE.search(decoded):
        flags.add("double_encoding")
    if "\x00" in decoded:
        flags.add("null_byte")
    return decoded, flags


def normalize_path(raw_path):
    decoded, flags = decode_once(raw_path)
    if "\\" in decoded:
        flags.add("backslash")
        decoded = decoded.replace("\\", "/")

    segments = []
    for segment in decoded.split("/"):
        if segment == "" or segment == ".":
            continue
        if segment == "..":
            flags.add("traversal")
            if segments:
                segments.pop()
            continue
        segments.append(segment)

    path = "/" + "/".join(segments)
    if decoded.endswith("/") and path != "/":
        path += "/"
    return path, flags


def normalize_request(request):
    flags = set()

    path, f = normalize_path(request.path)
    flags |= f

    query, f = decode_once(request.query, plus=True)
    flags |= f

    params = []
    for part in request.query.split("&"):
        if part == "":
            continue
        name, _, value = part.partition("=")
        name, f1 = decode_once(name, plus=True)
        value, f2 = decode_once(value, plus=True)
        flags |= f1 | f2
        params.append((name, value))

    body_text = request.body.decode("utf-8", errors="replace")
    content_type = request.headers.get("content-type", "").lower()
    if content_type.startswith("application/x-www-form-urlencoded"):
        body_text, f = decode_once(body_text, plus=True)
        flags |= f

    return NormalizedRequest(
        original=request,
        path=path,
        query=query,
        params=params,
        body_text=body_text,
        headers=dict(request.headers),
        flags=sorted(flags),
    )