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

# "Example.com:8080" -> ("example.com", 8080); no port given means the HTTP default, 80
def split_host_port(host_header):
    domain, _, port = host_header.partition(":")
    return domain.lower(), int(port) if port.isdigit() else 80

# stateless rule checking engine
def check_rules(client_ip, headers):
    if client_ip in BLOCKED_IPS:
        return "BLOCK", f"client IP {client_ip} is blocklisted"

    domain, port = split_host_port(headers.get("Host", ""))
    if port not in ALLOWED_PORTS:
        return "BLOCK", f"destination port {port} is not allowed"

    if domain_is_blocked(domain):
        return "BLOCK", f"domain {domain} is blocklisted"

    return "ALLOW", "no matching rule"
