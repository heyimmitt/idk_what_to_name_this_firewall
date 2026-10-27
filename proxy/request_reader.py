import time

from proxy.http_parser import parse_request

MAX_HEADER_BYTES = 16 * 1024      # request line + all headers
MAX_BODY_BYTES = 1024 * 1024      # 1 MB of request body
REQUEST_TIMEOUT_SECONDS = 10      # the WHOLE request must arrive within this
IDLE_TIMEOUT_SECONDS = 60         # after that, how long a send/recv may stall

# raised when the request can't be read; carries the HTTP status to reply with
class RequestError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status      # e.g. "408 Request Timeout"

# one recv that must finish before the deadline. The timeout is set to the time
# LEFT, not a fixed 10s -- otherwise a client sending 1 byte every 9s (slowloris)
# would reset the clock on every recv and never time out
def recv_before(sock, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RequestError("408 Request Timeout", "request took too long to arrive")
    sock.settimeout(remaining)
    try:
        return sock.recv(4096)
    except TimeoutError:
        raise RequestError("408 Request Timeout", "request took too long to arrive")

# reads exactly ONE complete HTTP request (headers + body) from the client.
# Returns the raw bytes, or None if the client connected and sent nothing at all.
def read_request(sock):
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS

    # 1. headers end at the first blank line -- keep reading until we've seen it
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > MAX_HEADER_BYTES:
            raise RequestError("431 Request Header Fields Too Large", "headers too large")
        chunk = recv_before(sock, deadline)
        if chunk == b"":   # client closed the connection
            if data == b"":
                return None   # browsers open speculative connections and never use them
            raise RequestError("400 Bad Request", "connection closed mid-request")
        data += chunk

    head, _, body = data.partition(b"\r\n\r\n")
    if len(head) > MAX_HEADER_BYTES:
        raise RequestError("431 Request Header Fields Too Large", "headers too large")

    # 2. use the normal parser to find the body length (one parser for everything)
    try:
        _, _, _, headers, _ = parse_request(head + b"\r\n\r\n")
    except ValueError as e:
        raise RequestError("400 Bad Request", str(e))

    if "transfer-encoding" in headers:
        # chunked bodies have no Content-Length; mixing the two is how request
        # smuggling works, so refuse rather than half-support it
        raise RequestError("501 Not Implemented", "Transfer-Encoding is not supported")

    length_string = headers.get("content-length", "0")
    if not (length_string.isascii() and length_string.isdigit()):
        raise RequestError("400 Bad Request", f"invalid Content-Length {length_string!r}")
    content_length = int(length_string)
    if content_length > MAX_BODY_BYTES:
        raise RequestError("413 Content Too Large", f"body over {MAX_BODY_BYTES} bytes")

    # 3. the body is exactly Content-Length bytes -- keep reading until we have them
    while len(body) < content_length:
        chunk = recv_before(sock, deadline)
        if chunk == b"":
            raise RequestError("400 Bad Request", "connection closed mid-body")
        body += chunk

    # from here on, a stalled client/destination just shouldn't hang us forever
    sock.settimeout(IDLE_TIMEOUT_SECONDS)

    # anything past Content-Length would be a second request; we only handle one
    return head + b"\r\n\r\n" + body[:content_length]
