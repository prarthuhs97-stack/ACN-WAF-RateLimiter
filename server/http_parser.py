from dataclasses import dataclass

MAX_HEADER_BYTES = 8192
MAX_BODY_BYTES = 1_000_000
SUPPORTED_METHODS = {"GET", "POST"}
SUPPORTED_VERSIONS = {"HTTP/1.0", "HTTP/1.1"}


class ParseError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Request:
    method: str
    path: str
    query: str
    version: str
    headers: dict
    body: bytes = b""
    client_ip: str = ""


def parse_request_head(head):
    text = head.decode("iso-8859-1")
    lines = text.split("\r\n")
    request_line = lines[0]
    header_lines = lines[1:]

    # --- request line ---
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise ParseError(400, "Malformed request line")
    method, target, version = parts

    if method not in SUPPORTED_METHODS:
        raise ParseError(501, "Method not implemented")
    if not version.startswith("HTTP/"):
        raise ParseError(400, "Malformed HTTP version")
    if version not in SUPPORTED_VERSIONS:
        raise ParseError(505, "HTTP version not supported")
    if not target.startswith("/"):
        raise ParseError(400, "Request target must start with /")

    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, ""

    # --- headers ---
    headers = {}
    for line in header_lines:
        if ":" not in line:
            raise ParseError(400, "Malformed header line")
        name, value = line.split(":", 1)
        if name == "" or " " in name or "\t" in name:
            raise ParseError(400, "Malformed header name")
        name = name.lower()
        value = value.strip()
        if name in headers:
            headers[name] += ", " + value
        else:
            headers[name] = value

    if version == "HTTP/1.1" and "host" not in headers:
        raise ParseError(400, "Missing Host header")
    if "transfer-encoding" in headers:
        raise ParseError(501, "Transfer-Encoding not supported")

    return Request(method, path, query, version, headers)


def get_content_length(headers):
    value = headers.get("content-length")
    if value is None:
        return 0
    if not (value.isascii() and value.isdigit()):
        raise ParseError(400, "Invalid Content-Length")
    length = int(value)
    if length > MAX_BODY_BYTES:
        raise ParseError(413, "Body too large")
    return length