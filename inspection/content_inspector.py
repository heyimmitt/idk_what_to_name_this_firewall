import json
import os
import re
from urllib.parse import unquote

PATTERNS_PATH = os.path.join(os.path.dirname(__file__), "patterns.json")
with open(PATTERNS_PATH) as f:
    patterns = json.load(f)

URL_SHORTENERS = set(patterns["url_shorteners"])
PHISHING_KEYWORDS = patterns["phishing_keywords"]
SUSPICIOUS_EXTENSIONS = patterns["suspicious_extensions"]

SCORE_THRESHOLD = 3   # score >= this -> BLOCK

IP_LITERAL_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# inspects an already-parsed request (domain + path + body), returns (score, [reasons])
def inspect_request(domain, path, body=""):
    score = 0
    reasons = []
    # unquote() reverses URL-encoding first, e.g. "verify%2Daccount" -> "verify-account",
    # so encoding a keyword can't be used to sneak past the keyword check below
    path_lower = unquote(path).lower()
    body_lower = unquote(body).lower()

    # 1. destination is a raw IP address instead of a domain name — a classic way
    #    to dodge domain blocklists, and unusual for a legitimate everyday site
    if IP_LITERAL_RE.match(domain):
        score += 3
        reasons.append(f"destination is an IP-literal URL ({domain}), not a domain name")

    # 2. known URL-shortener domain — hides the real destination behind a redirect
    if domain in URL_SHORTENERS:
        score += 3
        reasons.append(f"{domain} is a known URL shortener")

    # 3. phishing-style keyword combos in the path/query
    for keyword in PHISHING_KEYWORDS:
        if keyword in path_lower:
            score += 3
            reasons.append(f"path contains phishing-like keyword '{keyword}'")

    # 3b. same keywords, but in the request BODY (e.g. a submitted form) — this is
    # actual payload content, not just the URL, which is what "content inspection" means
    for keyword in PHISHING_KEYWORDS:
        if keyword in body_lower:
            score += 3
            reasons.append(f"request body contains phishing-like keyword '{keyword}'")

    # 4. suspicious file extension being requested
    for ext in SUSPICIOUS_EXTENSIONS:
        if path_lower.endswith(ext):
            score += 3
            reasons.append(f"path requests a suspicious file type ({ext})")

    return score, reasons

# returns (verdict, reason) like check_rules, so interceptor.py can treat them the same way
def check_content(domain, path, body=""):
    score, reasons = inspect_request(domain, path, body)
    if score >= SCORE_THRESHOLD:
        return "BLOCK", f"content inspection score {score} >= {SCORE_THRESHOLD}: " + "; ".join(reasons)
    return "ALLOW", "no suspicious content detected"
