import socket

HOST = "0.0.0.0"
PORT = 8080

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(50)
    print(f"Listening on {HOST}:{PORT}")

    while True:
        client_socket, client_addr = server_socket.accept()
        print(f"Connection from {client_addr}")

        data = client_socket.recv(4096)
        print(data.decode("iso-8859-1"))

        body = "Hello from my server\n"
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        client_socket.sendall(response.encode())
        client_socket.close()

if __name__ == "__main__":
    main()