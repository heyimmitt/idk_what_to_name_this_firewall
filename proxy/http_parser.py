from urllib.parse import urlsplit

# parser — reads raw bytes, extracts request line + headers + body
def parse_request(data):
    # split on the blank-line boundary in the raw bytes first, so a body containing
    # arbitrary bytes doesn't get mangled by decoding/splitting it as text too early
    head_bytes, _, body_bytes = data.partition(b"\r\n\r\n")
    body = body_bytes.decode(errors="replace")

    text = head_bytes.decode(errors="replace")  # bytes -> string; be tolerant of odd bytes
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

    # header names are case-insensitive in HTTP ("Host" == "host" == "HOST"), so
    # store them all lowercased and always look them up lowercased too
    headers = {}
    for line in lines[1:]:
        if line == "":       # blank line marks end of headers
            break
        name, sep, value = line.partition(":")   # the space after ":" is optional
        if not sep or name == "" or name != name.strip():
            # no colon, empty name, or whitespace around the name ("Host : x") --
            # the HTTP spec says to reject these, since servers disagree on them
            raise ValueError(f"malformed header line {line!r}")
        name = name.lower()
        value = value.strip()

        if name in headers:
            if name in ("host", "content-length"):
                # two of these means the firewall might check one while the
                # destination uses the other, so refuse instead of picking one
                raise ValueError(f"duplicate {name} header")
            headers[name] += ", " + value   # standard way to merge repeated headers
        else:
            headers[name] = value

    # absolute-form (browser -> proxy): "GET http://site.com/a?b=1 HTTP/1.1"
    # convert to origin-form: path becomes "/a?b=1" and the site goes into host
    if path.lower().startswith("http://"):   # URL schemes are case-insensitive
        url = urlsplit(path)
        # netloc is the raw "host:port" text (possibly with "user:pass@" in front);
        # pass it on as-is and let normalize_host do all the interpreting
        headers["host"] = url.netloc.rpartition("@")[2]
        path = url.path or "/"
        if url.query:
            path += "?" + url.query

    return method, path, version, headers, body
