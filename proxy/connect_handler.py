import select

from proxy.address import connect_to

# blind tunnel for HTTPS: relays raw (encrypted) bytes between the client and the
# destination in both directions without being able to read them
def tunnel(client_socket, ips, port):
    try:
        dest_socket = connect_to(ips, port)   # the already-checked IPs, not the name
    except OSError as e:
        body = f"502 Bad Gateway: could not reach port {port} ({e})\n".encode()
        client_socket.sendall(
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        return

    # tells the browser the tunnel is open; it now starts its TLS handshake through us
    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    try:
        while True:
            # sleep until either side has data (or 60s pass with no traffic at all)
            readable, _, _ = select.select([client_socket, dest_socket], [], [], 60)
            if not readable:
                break

            for sock in readable:
                chunk = sock.recv(4096)
                if chunk == b"":          # one side closed, so the tunnel is over
                    return
                other = dest_socket if sock is client_socket else client_socket
                other.sendall(chunk)
    except OSError:                        # connection reset etc.
        pass
    finally:
        dest_socket.close()
