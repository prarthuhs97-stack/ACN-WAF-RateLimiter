import socket
import threading

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


def handle_request(request):
    lines = [
        f"method : {request.method}",
        f"path   : {request.path}",
        f"query  : {request.query}",
        f"version: {request.version}",
        f"client : {request.client_ip}",
        "headers:",
    ]
    for name, value in request.headers.items():
        lines.append(f"  {name}: {value}")
    lines.append(f"body   : {request.body!r}")
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
    return handle_request(request)


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