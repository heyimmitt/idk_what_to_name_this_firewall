import socket
import threading

from config import HOST, PORT
from audit.logger import logger, setup_logging, log_decision
from proxy.http_parser import parse_request
from proxy.request_reader import read_request, RequestError
from proxy.address import normalize_host, resolve
from proxy.forwarder import forward_request
from proxy.connect_handler import tunnel
from rules.stateless_rules import check_rules, check_destination_ips
from inspection.content_inspector import check_content
from state.connection_tracker import register_connection, release_connection, cleanup_loop

# handles everything for ONE client connection (runs in its own thread)
def handle_client(client_socket, client_addr):
    client_ip = client_addr[0]

    allowed, reason = register_connection(client_ip)
    if not allowed:
        log_decision(client_addr, "-", "BLOCK", "tracker", reason)   # request not read yet
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
    # read ONE complete request (all headers + the full body), within a time limit
    try:
        data = read_request(client_socket)
    except RequestError as e:   # too slow, too big, malformed, unsupported...
        log_decision(client_addr, "-", "REJECT", "reader", f"{e.status}: {e}")
        body = f"{e.status}: {e}\n".encode()
        client_socket.sendall(
            b"HTTP/1.1 " + e.status.encode() + b"\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        client_socket.close()
        return
    except OSError:   # client reset the connection while we were reading
        client_socket.close()
        return
    if data is None:   # browsers open speculative connections that never send anything
        client_socket.close()
        return

    try:
        method, path, version, headers, req_body = parse_request(data)
    except ValueError as e:   # malformed request line or header
        log_decision(client_addr, "-", "REJECT", "parser", str(e))
        client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        client_socket.close()
        return
    # hidden unless LOG_LEVEL is DEBUG -- handy when debugging, too noisy otherwise
    logger.debug(f"{client_addr[0]}:{client_addr[1]} | parsed {method} {path} {version} | headers {headers}")

    # pick where this request is ACTUALLY going, normalize it ONCE, and use that same
    # (host, port) for both the checks and the connection -- if the checks read one
    # value and the connection used another, a client could lie in one of them
    if method == "CONNECT":
        target, default_port = path, 443   # "CONNECT host:port" -- Host header is ignored
    else:
        target, default_port = headers.get("host", ""), 80   # parser put absolute-URL host here
    try:
        dest_host, dest_port = normalize_host(target, default_port)
    except ValueError as e:   # missing Host, bad port, etc. -- refuse, don't guess
        log_decision(client_addr, f"{method} {target or '(no host)'}", "REJECT", "parser", str(e))
        body = f"400 Bad Request: {e}\n".encode()
        client_socket.sendall(
            b"HTTP/1.1 400 Bad Request\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        client_socket.close()
        return
    request = f"{method} {dest_host}:{dest_port}"   # how this request appears in the log

    # catch-all: anything unexpected below still gets a real HTTP response instead
    # of silently killing the thread and leaving the client with nothing (which
    # browsers show as "did not send any data" / ERR_EMPTY_RESPONSE)
    try:
        # "stage" remembers which check produced the current verdict, for the log
        verdict, reason = check_rules(client_addr[0], dest_host, dest_port)
        stage = "rules"

        # content heuristics only need the name/path/body, not the network -- so they
        # run BEFORE the DNS lookup: cheap checks first, and a phishing domain gets a
        # proper 403 + reason even if it doesn't resolve
        if verdict == "ALLOW":
            # HTTPS path/body are encrypted, so CONNECT only gets the domain-based
            # heuristics (IP literal, shortener, lookalike, TLD...)
            if method == "CONNECT":
                verdict, reason = check_content(dest_host, "", "")
            else:
                verdict, reason = check_content(dest_host, path, req_body)
            stage = "content"

        # a name isn't what we connect to, its IPs are -- so resolve once, check
        # those IPs, and later connect to exactly these (never re-resolve)
        if verdict == "ALLOW":
            dest_ips = resolve(dest_host, dest_port)   # DNS failure -> OSError -> 502 below
            verdict, reason = check_destination_ips(dest_ips)
            stage = "dest-ip"

        if verdict == "ALLOW" and method == "CONNECT":
            # logged BEFORE tunnelling, since a tunnel can stay open for minutes
            log_decision(client_addr, request, "ALLOW", "passed", f"tunnel opened to {dest_ips[0]}")
            tunnel(client_socket, dest_ips, dest_port)   # the IPs we just checked
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
            response = forward_request(dest_ips, dest_port, data)
            status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")   # "HTTP/1.1 200 OK"
            stage, reason = "passed", f"forwarded to {dest_ips[0]}, destination replied '{status_line}'"
    except OSError as e:  # DNS failure, timeout, connection refused...
        verdict, stage, reason = "ERROR", "upstream", f"could not reach destination ({e})"
        body = f"502 Bad Gateway: could not reach destination ({e})\n".encode()
        response = (
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
    except Exception as e:
        # logger.exception also writes the full traceback (file + line) into the log
        logger.exception("unexpected error while handling a request")
        verdict, stage, reason = "ERROR", "internal", f"{type(e).__name__}: {e}"
        body = b"500 Internal Server Error\n"
        response = (
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )

    log_decision(client_addr, request, verdict, stage, reason)   # exactly one line per request

    client_socket.sendall(response)

    client_socket.close()

# connection intercepter
def run():
    setup_logging()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket using ipv4 and tcp
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # lets you reuse the same
    # address so you can restart without hitting the address already in use

    server_socket.bind((HOST, PORT)) # reserves the address 127.0.0.1:8080 as this socket's address
    server_socket.listen() # aceepts incoming connection attempts into a queue, without handing them to the code
    logger.info(f"Listening on {HOST}:{PORT}...")

    threading.Thread(target=cleanup_loop, daemon=True).start()  # periodic stale-entry sweep

    while True:
        client_socket, client_addr = server_socket.accept() # program pauses here until a client actually connects
        logger.debug(f"Accepted connection from {client_addr}")
        # accept() returns two things: a brand-new socket (client_socket) dedicated to that one client
        # (separate from server_socket, which keeps listening for others), and client_addr, a tuple like ('127.0.0.1', 54321)
        # — the client's IP and the ephemeral port it connected from.

        # hand this client to its own thread so the loop can immediately accept the next one
        threading.Thread(target=handle_client, args=(client_socket, client_addr), daemon=True).start()
