import socket

# rewrites/adds a "Connection: close" header so the destination closes the
# connection after replying — lets us reliably read the full response by
# looping recv() until it closes, instead of guessing when the body ends
def force_connection_close(data):
    lines = data.decode(errors="replace").split("\r\n")
    lines = [line for line in lines if not line.lower().startswith("connection:")]
    lines.insert(1, "Connection: close")  # right after the request line
    return "\r\n".join(lines).encode()

# opens a connection to the real destination, forwards the original request,
# and returns whatever response comes back
def forward_request(headers, data):
    host_header = headers.get("Host", "")
    parts = host_header.split(":")
    dest_host = parts[0]
    dest_port = int(parts[1]) if len(parts) > 1 else 80

    data = force_connection_close(data)

    dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_socket.connect((dest_host, dest_port))
    dest_socket.sendall(data)

    response = b""
    while True:
        chunk = dest_socket.recv(4096)
        if chunk == b"":   # destination closed the connection — response is complete
            break
        response += chunk

    dest_socket.close()
    return response
