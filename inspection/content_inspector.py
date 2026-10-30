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
WORD_RE = re.compile(r"[^\W_]+")   # runs of letters/digits; everything else separates words

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

# decoded text split into words, so "verify_account", "verify account",
# "verify.account", "action=verify&what=account" all give [..."verify", "account"]
def to_words(text):
    return WORD_RE.findall(text)

URL_SHORTENERS = set(patterns["url_shorteners"])
# phrases are processed exactly like the traffic, so the two compare like-for-like
PHISHING_ACTIONS = set(patterns["phishing_actions"])
PHISHING_TARGETS = set(patterns["phishing_targets"])
PHISHING_WINDOW = patterns["phishing_window"]
PHISHING_PHRASES = [" ".join(to_words(decode_fully(p))) for p in patterns["phishing_phrases"]]
# compiled once at startup; IGNORECASE so rule authors don't have to think about case
ATTACK_SIGNATURES = [
    (s["name"], re.compile(s["pattern"], re.IGNORECASE)) for s in patterns["attack_signatures"]
]
SUSPICIOUS_EXTENSIONS = patterns["suspicious_extensions"]
BRAND_NAMES = patterns["brand_names"]
SUSPICIOUS_DOMAIN_WORDS = patterns["suspicious_domain_words"]
REAL_BRAND_DOMAINS = set(patterns["real_brand_domains"])
SUSPICIOUS_TLDS = patterns["suspicious_tlds"]
MAX_HYPHENS = patterns["max_hyphens"]

SCORE_THRESHOLD = 3   # score >= this -> BLOCK

# true if domain is one of these, or a subdomain of one ("www.bit.ly" -> "bit.ly").
# the "." matters: "notbit.ly" must NOT count as a subdomain of "bit.ly"
def matches_domain(domain, domain_set):
    return any(domain == d or domain.endswith("." + d) for d in domain_set)

DOMAIN_WORD_SPLIT_RE = re.compile(r"[.\-]+")

# "paypal.com.secure-login.net" -> ["paypal", "com", "secure", "login", "net"]
def domain_words(domain):
    return [w for w in DOMAIN_WORD_SPLIT_RE.split(domain) if w]

# a brand counts if a domain word IS it ("paypal-login") or STARTS with it
# ("paypallogin") -- but not in the middle/end of a word, so "purchase" doesn't
# count as mentioning "chase", and "first" doesn't count as mentioning "irs"
def find_brand(words):
    for brand in BRAND_NAMES:
        if any(word.startswith(brand) for word in words):
            return brand
    return None

# finds an action word ("verify") within PHISHING_WINDOW words of a target word
# ("account"), in either order -- two short word lists cover hundreds of phrasings
# ("verify your account", "your account has been suspended", "confirm billing")
def find_phishing_combo(words):
    for i, word in enumerate(words):
        if word in PHISHING_ACTIONS:
            nearby = words[max(0, i - PHISHING_WINDOW): i + PHISHING_WINDOW + 1]
            target = next((w for w in nearby if w in PHISHING_TARGETS), None)
            if target:
                return word, target
    return None

# scam phrases that aren't an action+target pair ("claim your prize"). Matched as
# whole-word sequences: the spaces around both sides stop "act now" matching
# inside "contact nowhere"
def find_phishing_phrases(words):
    text = " " + " ".join(words) + " "
    return [p for p in PHISHING_PHRASES if " " + p + " " in text]

# names of the attack signatures this text matches, each name listed once (several
# SQL injection regexes matching still counts as one "SQL injection")
def find_attack_signatures(text):
    found = []
    for name, regex in ATTACK_SIGNATURES:
        if name not in found and regex.search(text):
            found.append(name)
    return found

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
    # attack signatures), "words" is just the words (for phishing wording)
    path_decoded = decode_fully(path)
    body_decoded = decode_fully(body)
    path_words = to_words(path_decoded)
    body_words = to_words(body_decoded)
    # path without the "?query" part, so "/setup.exe?x=1" still ends in ".exe"
    path_only = path_decoded.split("?", 1)[0]

    # 1. destination is a raw IP address instead of a domain name — a classic way
    #    to dodge domain blocklists, and unusual for a legitimate everyday site
    if is_ip_literal(domain):
        score += 3
        reasons.append(f"destination is an IP-literal URL ({domain}), not a domain name")

    # 2. known URL-shortener domain — hides the real destination behind a redirect
    if matches_domain(domain, URL_SHORTENERS):
        score += 3
        reasons.append(f"{domain} is a known URL shortener")

    # 2b. brand impersonation: domain mentions a real brand name AND a suspicious
    # word (e.g. "paypal-secure-login.net"), but isn't actually that brand's real
    # domain (or a subdomain of it) — catches lookalikes we've never seen before,
    # instead of needing every fake domain listed individually
    if not matches_domain(domain, REAL_BRAND_DOMAINS):
        mentioned_brand = find_brand(domain_words(domain))
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

    # 3. phishing-style wording, in the path/query AND the request body (e.g. a
    # submitted form) -- the body is actual payload content, which is what
    # "content inspection" means
    for where, words in (("path", path_words), ("request body", body_words)):
        combo = find_phishing_combo(words)
        if combo:
            score += 3
            reasons.append(f"{where} pairs '{combo[0]}' with '{combo[1]}' (phishing-style wording)")
        for phrase in find_phishing_phrases(words):
            score += 3
            reasons.append(f"{where} contains scam phrase '{phrase}'")

    # 4. suspicious file extension being requested
    for ext in SUSPICIOUS_EXTENSIONS:
        if path_only.endswith(ext):
            score += 3
            reasons.append(f"path requests a suspicious file type ({ext})")

    # 5. known attack signatures (path traversal, SQL injection, XSS) -- attacks on
    # the SERVER rather than the user. Run on the decoded text, so "%2e%2e%2f" and
    # "union+select" are caught by plain "../" and "union select" patterns
    for where, text in (("path", path_decoded), ("request body", body_decoded)):
        for name in find_attack_signatures(text):
            score += 3
            reasons.append(f"{where} matches attack signature: {name}")

    return score, reasons

# returns (verdict, reason) like check_rules, so interceptor.py can treat them the same way
def check_content(domain, path, body=""):
    score, reasons = inspect_request(domain, path, body)
    if score >= SCORE_THRESHOLD:
        return "BLOCK", f"content inspection score {score} >= {SCORE_THRESHOLD}: " + "; ".join(reasons)
    return "ALLOW", "no suspicious content detected"
