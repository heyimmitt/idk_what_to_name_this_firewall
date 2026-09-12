# parser — reads raw bytes, extracts request line + headers
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
