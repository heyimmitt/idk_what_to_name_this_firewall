import socket

HOST = "127.0.0.1"
PORT = 8080

# parser — reads raw bytes, extracts src/dst IP, port, protocol
def parse_request(data):
    text = data.decode(errors="replace")  # bytes -> string; be tolerant of odd bytes
    lines = text.split("\r\n")

    """
    A request looks like:
    GET /index.html HTTP/1.1\r\n
    Host: example.com\r\n
    User-Agent: curl/8.1.2\r\n
    \r\n
    """

    request_line = lines[0]              # e.g. "GET /index.html HTTP/1.1"
    method, path, version = request_line.split(" ")

    headers = {}
    for line in lines[1:]:
        if line == "":       # blank line marks end of headers
            break
        name, value = line.split(": ", 1)
        headers[name] = value

    return method, path, version, headers


BLOCKED_DOMAINS = {"badsite.com"}
BLOCKED_IPS = {"6.6.6.6"}

# stateless rule checking engine
def check_rules(client_ip, headers):
    if client_ip in BLOCKED_IPS:
        return "BLOCK", f"client IP {client_ip} is blocklisted"

    host = headers.get("Host", "")
    domain = host.split(":")[0]  # strip port, e.g "badsite.com:8080" -> "badsite.com"
    if domain in BLOCKED_DOMAINS:
        return "BLOCK", f"domain {domain} is blocklisted"

    return "ALLOW", "no matching rule"

# connection intercepter 
def main():
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

if __name__ == "__main__":
    main()
