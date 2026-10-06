STATUS_REASONS = {
    200: "OK",
    400: "Bad Request",
    408: "Request Timeout",
    413: "Payload Too Large",
    431: "Request Header Fields Too Large",
    501: "Not Implemented",
    505: "HTTP Version Not Supported",
}


def build_response(status, body="", content_type="text/plain"):
    reason = STATUS_REASONS.get(status, "Unknown")
    body_bytes = body.encode("utf-8")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return head.encode("iso-8859-1") + body_bytes