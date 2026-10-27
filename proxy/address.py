import ipaddress
import re
import socket

# only these characters can appear in an unusual spelling of an IPv4 address:
# decimal (1572395042), hex (0x5db8d822), octal (0135.0270.0330.042), short (127.1)
NUMERIC_HOST_RE = re.compile(r"^[0-9a-fx.]+$")

# turns any host string ("Example.COM.:8080", "[::1]:443", "1572395042") into one
# clean (host, port) pair, so every part of the firewall agrees on what the
# destination actually is. Raises ValueError if it can't be understood.
def normalize_host(host_string, default_port):
    host_string = host_string.strip()

    # 1. split host from port. IPv6 addresses contain colons themselves, so they
    #    come wrapped in brackets: "[2001:db8::1]:443"
    if host_string.startswith("["):
        end = host_string.find("]")
        if end == -1:
            raise ValueError(f"unclosed bracket in host {host_string!r}")
        host = host_string[1:end]
        rest = host_string[end + 1:]          # "" or ":443"
        if rest and not rest.startswith(":"):
            raise ValueError(f"unexpected text after ']' in host {host_string!r}")
        port_string = rest[1:]
    else:
        host, _, port_string = host_string.partition(":")
        if ":" in port_string:                # more than one colon, but no brackets
            raise ValueError(f"malformed host {host_string!r}")

    # 2. no port means the default; anything else must be a real port number
    if port_string == "":
        port = default_port
    elif port_string.isascii() and port_string.isdigit() and 1 <= int(port_string) <= 65535:
        port = int(port_string)
    else:
        raise ValueError(f"invalid port {port_string!r}")

    # 3. DNS names are case-insensitive, and "badsite.com." (trailing dot) is the
    #    same site as "badsite.com", so both must look identical to the blocklist
    host = host.lower().rstrip(".")
    if host == "":
        raise ValueError("empty host")

    # 4. rewrite any spelling of an IP address into its standard form, so IP checks
    #    see the same address the OS will actually connect to
    if NUMERIC_HOST_RE.match(host):
        try:
            # inet_aton parses IPv4 the same lenient way the OS does; inet_ntoa
            # turns the result back into normal dotted form
            host = socket.inet_ntoa(socket.inet_aton(host))
        except OSError:
            pass   # only looked numeric (e.g. "add.cafe"), it's a real domain name
    else:
        try:
            host = str(ipaddress.ip_address(host))   # standard IPv6 form
        except ValueError:
            pass   # an ordinary domain name, leave it alone

    return host, port

# looks up every IP a host resolves to (a domain can have several, IPv4 and IPv6).
# Raises OSError if the lookup fails.
def resolve(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = [info[4][0] for info in infos]   # info[4] is the (ip, port, ...) address
    return list(dict.fromkeys(ips))         # drop duplicates, keep the order

# connects to the first of these IPs that answers. These are the SAME addresses the
# rules already checked -- calling create_connection with the hostname instead would
# do a second DNS lookup, which could return a different, unchecked address
def connect_to(ips, port, timeout=10):
    last_error = OSError("no addresses to connect to")
    for ip in ips:
        try:
            return socket.create_connection((ip, port), timeout=timeout)
        except OSError as e:
            last_error = e
    raise last_error
