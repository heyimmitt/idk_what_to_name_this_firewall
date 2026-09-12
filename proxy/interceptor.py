import socket

from config import HOST, PORT
from proxy.http_parser import parse_request
from rules.stateless_rules import check_rules

# connection intercepter
def run():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket using ipv4 and tcp
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # lets you reuse the same
    # address so you can restart without hitting the address already in use

    server_socket.bind((HOST, PORT)) # reserves the address 127.0.0.1:8080 as this socket's address
    server_socket.listen() # aceepts incoming connection attempts into a queue, without handing them to the code
    print(f"Listening on {HOST}:{PORT}...")

    while True:
        client_socket, client_addr = server_socket.accept() # program pauses here until a client actually connects
        print(f"Accepted connection from {client_addr}")
        # accept() returns two things: a brand-new socket (client_socket) dedicated to that one client
        # (separate from server_socket, which keeps listening for others), and client_addr, a tuple like ('127.0.0.1', 54321)
        # — the client's IP and the ephemeral port it connected from.

        data = client_socket.recv(4096) # reads upto 4096 bytes from the client socket
        print("Received:")
        print(data)

        method, path, version, headers = parse_request(data)
        print(f"Parsed: method={method} path={path} version={version}")
        print(f"Headers: {headers}")

        verdict, reason = check_rules(client_addr[0], headers)
        print(f"Verdict: {verdict} ({reason})")

        if verdict == "BLOCK":
            body = f"403 Forbidden: {reason}\n".encode()
            status_line = b"HTTP/1.1 403 Forbidden\r\n"
        else:
            body = b"Hello from the firewall proxy!\n"
            status_line = b"HTTP/1.1 200 OK\r\n"

        response = (
            status_line +
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        client_socket.sendall(response)

        client_socket.close()
