import socket
import threading

from config import HOST, PORT
from proxy.http_parser import parse_request
from proxy.forwarder import forward_request
from proxy.connect_handler import tunnel
from rules.stateless_rules import check_rules
from state.connection_tracker import register_connection, release_connection

# handles everything for ONE client connection (runs in its own thread)
def handle_client(client_socket, client_addr):
    client_ip = client_addr[0]

    allowed, reason = register_connection(client_ip)
    if not allowed:
        print(f"Connection tracker: BLOCK ({reason})")
        body = f"429 Too Many Requests: {reason}\n".encode()
        client_socket.sendall(
            b"HTTP/1.1 429 Too Many Requests\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        client_socket.close()
        return

    try:
        handle_allowed_client(client_socket, client_addr)
    finally:
        release_connection(client_ip)   # always runs, so the count never leaks

def handle_allowed_client(client_socket, client_addr):
    data = client_socket.recv(4096) # reads upto 4096 bytes from the client socket
    if not data:   # browsers open speculative connections that never send anything
        client_socket.close()
        return

    print("Received:")
    print(data)

    try:
        method, path, version, headers = parse_request(data)
    except ValueError:   # malformed request line or header
        client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        client_socket.close()
        return
    print(f"Parsed: method={method} path={path} version={version}")
    print(f"Headers: {headers}")

    verdict, reason = check_rules(client_addr[0], headers)
    print(f"Verdict: {verdict} ({reason})")

    if verdict == "ALLOW" and method == "CONNECT":
        tunnel(client_socket, path)   # for CONNECT, "path" is "host:port"
        client_socket.close()
        return

    if verdict == "BLOCK":
        body = f"403 Forbidden: {reason}\n".encode()
        response = (
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
    else:
        try:
            response = forward_request(headers, data)
        except OSError as e:  # DNS failure, timeout, connection refused...
            body = f"502 Bad Gateway: could not reach destination ({e})\n".encode()
            response = (
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )

    print("Response:")
    print(response)

    client_socket.sendall(response)

    client_socket.close()

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

        # hand this client to its own thread so the loop can immediately accept the next one
        threading.Thread(target=handle_client, args=(client_socket, client_addr), daemon=True).start()
