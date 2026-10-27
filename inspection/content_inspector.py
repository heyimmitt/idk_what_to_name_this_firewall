import ipaddress
import json
import os
import re
import unicodedata
from urllib.parse import unquote_plus

PATTERNS_PATH = os.path.join(os.path.dirname(__file__), "patterns.json")
with open(PATTERNS_PATH) as f:
    patterns = json.load(f)

# --- normalization: get text into ONE standard form before matching anything ---

MAX_DECODE_ROUNDS = 5
SEPARATORS_RE = re.compile(r"[\s\-_./+]+")   # any run of these counts as one separator

# the real text the server will end up seeing
def decode_fully(text):
    # decode repeatedly: "%252D" -> "%2D" -> "-". Decoding once (like before) let
    # double-encoded keywords through, since the server decodes again after us
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote_plus(text)   # "_plus": "+" means space in forms/query strings
        if decoded == text:
            break
        text = decoded
    # NFKC turns unicode lookalikes into plain characters ("ｖｅｒｉｆｙ" -> "verify")
    return unicodedata.normalize("NFKC", text).lower()

# decoded text with every run of separators squashed to a single "-", so
# "verify_account", "verify account", "verify.account" all become "verify-account"
def flatten(text):
    return SEPARATORS_RE.sub("-", text)

URL_SHORTENERS = set(patterns["url_shorteners"])
# flattened the same way as the traffic, so the two always compare like-for-like
PHISHING_KEYWORDS = [flatten(decode_fully(k)) for k in patterns["phishing_keywords"]]
SUSPICIOUS_EXTENSIONS = patterns["suspicious_extensions"]
BRAND_NAMES = patterns["brand_names"]
SUSPICIOUS_DOMAIN_WORDS = patterns["suspicious_domain_words"]
REAL_BRAND_DOMAINS = set(patterns["real_brand_domains"])
SUSPICIOUS_TLDS = patterns["suspicious_tlds"]
MAX_HYPHENS = patterns["max_hyphens"]

SCORE_THRESHOLD = 3   # score >= this -> BLOCK

# domain is already normalized (proxy/address.py), so any IP spelling has become a
# standard IPv4/IPv6 string by now -- ipaddress recognises both
def is_ip_literal(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

# inspects an already-parsed request (domain + path + body), returns (score, [reasons])
def inspect_request(domain, path, body=""):
    score = 0
    reasons = []
    # two views of each: "decoded" keeps real "." and "/" (for file extensions and
    # attack signatures), "flat" squashes separators (for keyword matching)
    path_decoded = decode_fully(path)
    body_decoded = decode_fully(body)
    path_flat = flatten(path_decoded)
    body_flat = flatten(body_decoded)
    # path without the "?query" part, so "/setup.exe?x=1" still ends in ".exe"
    path_only = path_decoded.split("?", 1)[0]

    # 1. destination is a raw IP address instead of a domain name — a classic way
    #    to dodge domain blocklists, and unusual for a legitimate everyday site
    if is_ip_literal(domain):
        score += 3
        reasons.append(f"destination is an IP-literal URL ({domain}), not a domain name")

    # 2. known URL-shortener domain — hides the real destination behind a redirect
    if domain in URL_SHORTENERS:
        score += 3
        reasons.append(f"{domain} is a known URL shortener")

    # 2b. brand impersonation: domain mentions a real brand name AND a suspicious
    # word (e.g. "paypal-secure-login.net"), but isn't actually that brand's real
    # domain (or a subdomain of it) — catches lookalikes we've never seen before,
    # instead of needing every fake domain listed individually
    is_real_brand_domain = domain in REAL_BRAND_DOMAINS or any(
        domain.endswith("." + real) for real in REAL_BRAND_DOMAINS
    )
    if not is_real_brand_domain:
        mentioned_brand = next((b for b in BRAND_NAMES if b in domain), None)
        mentioned_word = next((w for w in SUSPICIOUS_DOMAIN_WORDS if w in domain), None)
        if mentioned_brand and mentioned_word:
            score += 3
            reasons.append(
                f"domain '{domain}' mentions brand '{mentioned_brand}' with suspicious "
                f"word '{mentioned_word}' but isn't {mentioned_brand}'s real domain"
            )

    # 2c. excessive hyphens — legitimate business domains rarely have many, scam
    # domains often do ("amazon-account-verify-update-now.com")
    if domain.count("-") > MAX_HYPHENS:
        score += 2
        reasons.append(f"domain '{domain}' has an unusually high number of hyphens ({domain.count('-')})")

    # 2d. suspicious TLD — weak signal alone (legitimate sites use these too), so it
    # only contributes a small amount and needs another signal to actually block
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 1
        reasons.append(f"domain '{domain}' uses a commonly-abused TLD")

    # 3. phishing-style keyword combos in the path/query
    for keyword in PHISHING_KEYWORDS:
        if keyword in path_flat:
            score += 3
            reasons.append(f"path contains phishing-like keyword '{keyword}'")

    # 3b. same keywords, but in the request BODY (e.g. a submitted form) — this is
    # actual payload content, not just the URL, which is what "content inspection" means
    for keyword in PHISHING_KEYWORDS:
        if keyword in body_flat:
            score += 3
            reasons.append(f"request body contains phishing-like keyword '{keyword}'")

    # 4. suspicious file extension being requested
    for ext in SUSPICIOUS_EXTENSIONS:
        if path_only.endswith(ext):
            score += 3
            reasons.append(f"path requests a suspicious file type ({ext})")

    return score, reasons

# returns (verdict, reason) like check_rules, so interceptor.py can treat them the same way
def check_content(domain, path, body=""):
    score, reasons = inspect_request(domain, path, body)
    if score >= SCORE_THRESHOLD:
        return "BLOCK", f"content inspection score {score} >= {SCORE_THRESHOLD}: " + "; ".join(reasons)
    return "ALLOW", "no suspicious content detected"
