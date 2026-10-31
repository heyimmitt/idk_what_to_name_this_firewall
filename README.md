# Application-Layer Firewall

A proxy-based firewall written in Python using only the standard library. A browser is configured to use it as its HTTP/HTTPS proxy; every request passes through a layered inspection pipeline and is either forwarded to the real destination or refused with a reason.

```
[Browser] → [Firewall proxy] → [Destination server]
```

## Pipeline

Each request goes through these stages in order, cheapest checks first. The first stage that says BLOCK decides.

1. **Interceptor** — accepts the TCP connection; one thread per client.
2. **Connection state tracker** — per-client-IP rate limit (new connections per 10 s) and concurrency limit (connections open at once). Returns 429 when exceeded.
3. **Request reader** — buffers until a *complete* request has arrived (headers up to the blank line, then exactly `Content-Length` body bytes). Enforces size limits (431 / 413) and a total time limit against slow-sending clients (408).
4. **Parser** — request line and headers (case-insensitive names); handles both origin-form (`GET /path`) and the absolute-form browsers send to proxies (`GET http://site/path`), plus `CONNECT host:port` for HTTPS. Malformed or ambiguous requests (duplicate `Host`, whitespace before `:`) are rejected with 400.
5. **Destination normalization** — the destination is worked out once (CONNECT target for HTTPS, otherwise the URL/Host) and normalized: lowercase, trailing dot removed, port validated, IPv6 brackets, and alternative IP spellings (`1572395042`, `0x5db8d822`) converted to dotted form. Every later stage uses this same value.
6. **Stateless rule engine** — client-IP blocklist, destination-port allowlist, domain blocklist (a blocked domain also blocks its subdomains).
7. **Content inspection engine** — scoring-based heuristics; score ≥ 3 blocks:
   - IP-literal destinations, known URL shorteners
   - brand impersonation (`paypal-secure-login.net`), matched on whole words so `purchase-update.com` isn't mistaken for "chase"
   - excessive hyphens, commonly-abused TLDs
   - phishing wording in the path or body: an action word (`verify`, `suspended`…) within 3 words of a target word (`account`, `billing`…), plus known scam phrases
   - suspicious file extensions (`.exe`, `.scr`…)
   - attack signatures: path traversal, SQL injection, cross-site scripting

   All text is fully URL-decoded (repeatedly) and Unicode-normalized first, so encoding tricks don't bypass the checks.
8. **Destination IP check** — the name is resolved, and *every* resulting IP is checked: blocklisted IPs and internal addresses (loopback, private LAN, link-local) are refused, which stops the proxy being used to reach itself or the internal network (SSRF). The proxy then connects to exactly these checked IPs, never re-resolving.
9. **Forward / tunnel** — HTTP: the request is rebuilt (origin-form request line, `Host` set to the checked destination, proxy-only headers removed, body passed through byte-for-byte) and the real response relayed back. HTTPS: a blind TCP tunnel.
10. **Logging & alerting** — one line per decision to the terminal and `logs/firewall.log` (rotated at 1 MB). Content-inspection blocks are logged at a distinct `ALERT` level.

### HTTPS limitation

HTTPS is relayed through a blind tunnel. The firewall only sees `CONNECT example.com:443`, so for HTTPS it can apply the domain, port and IP rules and the domain-based heuristics, but **not** path, keyword, body or signature inspection. Inspecting HTTPS content would require TLS interception (MITM: the firewall terminating TLS with its own CA certificate), which is not implemented.

## Project structure

```
main.py                     entry point
config.py                   HOST, PORT
proxy/
  interceptor.py            accept loop, per-connection pipeline
  request_reader.py         reads one complete request (limits + timeouts)
  http_parser.py            request line + headers + body
  address.py                host normalization, DNS resolution, connecting to checked IPs
  forwarder.py              rebuilds the request, forwards it, returns the response
  connect_handler.py        blind CONNECT tunnel for HTTPS
rules/
  stateless_rules.py        IP / port / domain / destination-IP rules
  blocklist.json            blocked client IPs, domains, ports, destination IPs, internal allowlist
  blocked_domains.txt       bulk domain blocklist (hosts-file format accepted)
state/
  connection_tracker.py     per-IP rate and concurrency limits
inspection/
  content_inspector.py      normalization + scoring heuristics + signatures
  patterns.json             all inspection word lists, phrases and regex signatures
audit/
  logger.py                 log format, ALERT level, file + console output
```

Rules and patterns live in the JSON/text files, so they can be changed without touching code (restart to reload).

## Running it

Requires Python 3.10+. No packages to install.

```bash
python3 main.py
```

Then either point a browser at it (Firefox: Settings → Network Settings → Manual proxy configuration → `127.0.0.1`, port `8080`, tick "Also use this proxy for HTTPS"), or use curl:

```bash
curl --proxy http://127.0.0.1:8080 http://example.com/                 # allowed
curl --proxy http://127.0.0.1:8080 http://badsite.com/                 # 403, blocklisted domain
curl --proxy http://127.0.0.1:8080 http://example.com/verify-account   # 403, content inspection
```

To use it from another machine, set `HOST = "0.0.0.0"` in `config.py`. On Windows PowerShell use `curl.exe` (plain `curl` is an alias for a different command). Browsers' "HTTPS-only" modes upgrade `http://` links to HTTPS, which skips content inspection, so turn that off when testing it.

See [TESTS.md](TESTS.md) for the full set of test commands.
