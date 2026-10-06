import socket
import threading
from normalizer import normalize_request
from rate_limiter import RateLimiter
from waf import WAF
from http_parser import (
    MAX_HEADER_BYTES,
    ParseError,
    get_content_length,
    parse_request_head,
)
from http_response import build_response

HOST = "0.0.0.0"
PORT = 8080
READ_TIMEOUT = 5  # seconds
RATE_LIMITER = RateLimiter.from_env()
WAF_ENGINE = WAF()
def read_request(client_socket):
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > MAX_HEADER_BYTES:
            raise ParseError(431, "Request headers too large")
        chunk = client_socket.recv(4096)
        if not chunk:
            if buffer:
                raise ParseError(400, "Incomplete request")
            return None
        buffer += chunk

    head, _, body = buffer.partition(b"\r\n\r\n")
    request = parse_request_head(head)

    length = get_content_length(request.headers)
    while len(body) < length:
        chunk = client_socket.recv(4096)
        if not chunk:
            raise ParseError(400, "Incomplete body")
        body += chunk
    request.body = body[:length]
    return request


def handle_request(request,normalized):
    normalized = normalize_request(request)
    lines = [
        "--- original (raw) ---",
        f"method : {request.method}",
        f"path   : {request.path!r}",
        f"query  : {request.query!r}",
        f"version: {request.version}",
        f"client : {request.client_ip}",
        f"body   : {request.body!r}",
        "--- normalized ---",
        f"path   : {normalized.path!r}",
        f"query  : {normalized.query!r}",
        f"params : {normalized.params!r}",
        f"body   : {normalized.body_text!r}",
        f"flags  : {normalized.flags!r}",
    ]
    return build_response(200, "\n".join(lines) + "\n")
def process_connection(client_socket, client_addr):
    try:
        request = read_request(client_socket)
    except ParseError as error:
        return build_response(error.status, error.message + "\n")
    except socket.timeout:
        return build_response(408, "Request timed out\n")

    if request is None:
        return None

    request.client_ip = client_addr[0]

    # Normalize before rate limiting.
    normalized = normalize_request(request)

    # Token Bucket rate limiter.
    decision = RATE_LIMITER.allow(request.client_ip)

    if not decision.allowed:
        body = b"429 Too Many Requests\n"
        headers = [
            "HTTP/1.1 429 Too Many Requests",
            "Content-Type: text/plain",
            "Content-Length: %d" % len(body),
            "Connection: close",
        ]

        if decision.retry_after:
            headers.append(
                "Retry-After: %d" % decision.retry_after
            )

        return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body

        # WAF inspection.
    verdict = WAF_ENGINE.inspect(normalized)

    if verdict.blocked:
        print(
            "[WAF] blocked ip=%s type=%s rule=%s loc=%s"
            % (
                request.client_ip,
                verdict.attack_type,
                verdict.rule,
                verdict.location,
            ),
            flush=True,
        )

        body = b"403 Forbidden: request blocked by WAF\n"
        headers = [
            "HTTP/1.1 403 Forbidden",
            "Content-Type: text/plain",
            "Content-Length: %d" % len(body),
            "Connection: close",
        ]

        return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body

    return handle_request(request, normalized)

    


def handle_client(client_socket, client_addr):
    try:
        client_socket.settimeout(READ_TIMEOUT)
        response = process_connection(client_socket, client_addr)
        if response is not None:
            client_socket.sendall(response)
    except OSError:
        pass
    finally:
        client_socket.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(50)
    print(f"Listening on {HOST}:{PORT}")

    while True:
        client_socket, client_addr = server_socket.accept()
        thread = threading.Thread(
            target=handle_client,
            args=(client_socket, client_addr),
            daemon=True,
        )
        thread.start()


if __name__ == "__main__":
    main()