from proxy.address import connect_to

# "hop-by-hop" headers describe the client<->proxy connection, not the request,
# so they're never passed on. "host" is replaced with the checked destination, and
# "expect" is dropped since we've already read the whole body
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-connection", "proxy-authorization",
    "te", "trailer", "upgrade", "expect", "host",
}

# the Host header value for a normalized destination: IPv6 needs its brackets
# back, and the port is only written when it isn't the HTTP default
def host_header_value(dest_host, dest_port):
    if ":" in dest_host:
        dest_host = f"[{dest_host}]"
    return dest_host if dest_port == 80 else f"{dest_host}:{dest_port}"

# builds the request we send to the destination. Only the HEADER section is
# rewritten -- the body is passed through as raw bytes, never decoded, so binary
# uploads arrive exactly as the client sent them
def build_upstream_request(data, method, path, version, dest_host, dest_port):
    head, _, body = data.partition(b"\r\n\r\n")
    # latin-1 maps every byte 0-255 to one character, so decode -> encode gives
    # back the exact same bytes, whatever odd characters a header contains
    header_lines = head.decode("latin-1").split("\r\n")[1:]   # [1:] skips the old request line
    kept = [
        line for line in header_lines
        if line.partition(":")[0].strip().lower() not in HOP_BY_HOP_HEADERS
    ]

    new_head = [
        f"Host: {host_header_value(dest_host, dest_port)}",   # the host we actually checked
        *kept,
        # destination closes the connection after replying, so we know the response
        # is complete when recv() returns nothing
        "Connection: close",
    ]
    # origin-form request line ("GET /a HTTP/1.1"), using the path the parser extracted
    request_line = f"{method} {path} {version}".encode()
    return request_line + b"\r\n" + "\r\n".join(new_head).encode("latin-1") + b"\r\n\r\n" + body

# opens a connection to the real destination, sends the (already rebuilt) request,
# and returns whatever response comes back
def forward_request(dest_ips, dest_port, upstream_request):
    # tries each already-checked IP in turn; gives up on each after 10s
    dest_socket = connect_to(dest_ips, dest_port)
    dest_socket.sendall(upstream_request)

    response = b""
    while True:
        chunk = dest_socket.recv(4096)
        if chunk == b"":   # destination closed the connection — response is complete
            break
        response += chunk

    dest_socket.close()
    return response
