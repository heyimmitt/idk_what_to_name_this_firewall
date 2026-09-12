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
