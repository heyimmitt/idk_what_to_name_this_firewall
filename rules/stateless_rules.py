import ipaddress
import json
import os

RULES_DIR = os.path.dirname(__file__)

# custom rules (IPs, extra domains) live in blocklist.json,
# the bulk domain list lives in blocked_domains.txt
with open(os.path.join(RULES_DIR, "blocklist.json")) as f:
    rules = json.load(f)

BLOCKED_IPS = set(rules["blocked_ips"])
BLOCKED_DOMAINS = set(d.lower() for d in rules["blocked_domains"])
ALLOWED_PORTS = set(rules["allowed_ports"])   # allowlist: any other destination port is denied

# ip_network accepts a single IP ("6.6.6.6") or a whole range ("10.0.0.0/8")
BLOCKED_DEST_NETWORKS = [ipaddress.ip_network(n) for n in rules["blocked_destination_ips"]]
# internal addresses are blocked by default; list any you DO want reachable here
# (e.g. the destination PC in the lab, which sits on a private LAN address)
ALLOWED_INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in rules["allowed_internal_destinations"]]

# hosts files also list local names we must never block
IGNORED_NAMES = {"localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0"}

def load_domain_file(path):
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip()      # drop comments and blank lines
            if not line:
                continue
            domain = line.split()[-1].lower()       # handles both "domain" and "0.0.0.0 domain"
            if domain not in IGNORED_NAMES:
                BLOCKED_DOMAINS.add(domain)

load_domain_file(os.path.join(RULES_DIR, "blocked_domains.txt"))

# checks the domain and each parent of it against the set:
# "www.badsite.com" -> "www.badsite.com", "badsite.com", "com"
def domain_is_blocked(domain):
    labels = domain.split(".")
    return any(".".join(labels[i:]) in BLOCKED_DOMAINS for i in range(len(labels)))

# stateless rule checking engine. dest_host/dest_port must already be normalized
# (see proxy/address.py), so this only compares, it never parses
def check_rules(client_ip, dest_host, dest_port):
    if client_ip in BLOCKED_IPS:
        return "BLOCK", f"client IP {client_ip} is blocklisted"

    if dest_port not in ALLOWED_PORTS:
        return "BLOCK", f"destination port {dest_port} is not allowed"

    if domain_is_blocked(dest_host):
        return "BLOCK", f"domain {dest_host} is blocklisted"

    return "ALLOW", "no matching rule"

# second rule pass, run on the IPs the destination actually resolved to. Blocks if
# ANY of them is bad, since connect_to may end up using any of them
def check_destination_ips(ips):
    for ip_string in ips:
        ip = ipaddress.ip_address(ip_string)

        if any(ip in net for net in BLOCKED_DEST_NETWORKS):
            return "BLOCK", f"destination IP {ip} is blocklisted"

        # not is_global = loopback (127.x, ::1), private LAN (10.x, 192.168.x...),
        # link-local (169.254.x), 0.0.0.0, etc. -- stops the proxy being used to reach
        # itself or machines inside the network (SSRF)
        is_internal = not ip.is_global or ip.is_multicast
        if is_internal and not any(ip in net for net in ALLOWED_INTERNAL_NETWORKS):
            return "BLOCK", f"destination IP {ip} is an internal address"

    return "ALLOW", "destination IPs ok"
