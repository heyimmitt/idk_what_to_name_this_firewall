# Manual test commands

Run `python3 main.py` first. All commands assume the firewall is on `127.0.0.1:8080`.
Watch the firewall's own terminal alongside these — it prints one log line per
request: client, request, verdict, which stage decided, and the reason. The same
lines are saved in `logs/firewall.log` (see section 12).

Expected codes: **403** = blocked, **400/408/413/431/501** = rejected as malformed /
too slow / too big / unsupported, **404** from example.com = got *through* the
firewall (the page just doesn't exist), **502** = destination unreachable.

On Windows PowerShell use `curl.exe` instead of `curl`. The `printf ... | nc` tests
need a Linux/macOS shell (`nc -w 3` if your `nc` has no `-q`).

## 1. Basic proxying (interceptor + parser + forwarding)

```bash
# plain allowed request — should be 200, real example.com content
curl --proxy http://127.0.0.1:8080 http://example.com/

# absolute-URI form (this is what a real browser sends through a proxy)
curl --proxy http://127.0.0.1:8080 http://neverssl.com/

# origin-form with an explicit Host header (destination via Host, not the URL)
curl -H "Host: pokemondb.net" http://127.0.0.1:8080/pokedex/espeon
```

## 2. Stateless rule engine — domain/IP/port

```bash
# blocked domain — 403
curl --proxy http://127.0.0.1:8080 http://badsite.com/

# subdomain of a blocked domain also blocked — 403
curl --proxy http://127.0.0.1:8080 http://www.badsite.com/

# blocked port (not in allowed_ports) — 403
curl --proxy http://127.0.0.1:8080 http://example.com:8081/

# allowed port (8080 is in the allowlist) — passes the rule check
curl --proxy http://127.0.0.1:8080 http://example.com:8080/
```

Client-IP blocking (`BLOCKED_IPS` in `rules/blocklist.json`) can't be demoed from a
single machine on localhost, since every request comes from `127.0.0.1`. Needs a
second real machine on the 3-PC lab setup, or add your own IP temporarily to test it.

## 3. HTTPS / CONNECT tunneling

```bash
# allowed HTTPS site — 200, real tunnel, browser TLS handshake happens through it
curl -v --proxy http://127.0.0.1:8080 https://example.com/

# blocked domain over HTTPS — CONNECT itself gets refused with 403
curl -v --proxy http://127.0.0.1:8080 https://badsite.com/

# blocked port over HTTPS
curl -v --proxy http://127.0.0.1:8080 https://example.com:22/
```

```bash
# domain-based heuristics DO apply to HTTPS (only the name is needed) — 403
curl -v --proxy http://127.0.0.1:8080 https://bit.ly/

# but path/body inspection does NOT: same URL, HTTP is 403, HTTPS goes through
curl -s -o /dev/null -w "%{http_code}\n" --proxy http://127.0.0.1:8080 "http://example.com/downloads/setup.exe?v=2"
curl -s -o /dev/null -w "%{http_code}\n" --proxy http://127.0.0.1:8080 "https://example.com/downloads/setup.exe?v=2"
```

It's a blind tunnel (encrypted bytes only): the firewall sees `CONNECT example.com:443`
and nothing else, so only domain/IP/port rules and domain heuristics apply to HTTPS.
Inspecting HTTPS paths/bodies would need MITM (not built).

## 4. Connection state tracker (rate + concurrency limits)

```bash
# single request — should be 200
curl --proxy http://127.0.0.1:8080 http://example.com/

# burst of 35 at once — some should come back 429 (rate limit), rest 200
for i in $(seq 1 35); do
  curl -s -o /dev/null -w "%{http_code} " --proxy http://127.0.0.1:8080 http://example.com/ &
done
wait
echo
```

## 5. Content inspection engine (HTTP only — see note in section 3)

```bash
# clean request — 200
curl -m 10 -o /dev/null -w "code=%{http_code}\n" --proxy http://127.0.0.1:8080 http://example.com/

# phishing keyword in the URL path — 403
curl -m 10 -o /dev/null -w "code=%{http_code}\n" --proxy http://127.0.0.1:8080 http://example.com/verify-account

# same keyword, URL-encoded (%2D = "-") — still 403, proves decoding works
curl -m 10 -o /dev/null -w "code=%{http_code}\n" --proxy http://127.0.0.1:8080 "http://example.com/verify%2Daccount"

# keyword hidden in a POST body instead of the URL — 403
curl -m 10 -o /dev/null -w "code=%{http_code}\n" --proxy http://127.0.0.1:8080 -X POST -d "please confirm-identity now" http://example.com/submit

# known URL shortener domain — 403
curl -m 10 -o /dev/null -w "code=%{http_code}\n" --proxy http://127.0.0.1:8080 http://bit.ly/something

# IP-literal destination instead of a domain name — 403
curl -m 10 -o /dev/null -w "code=%{http_code}\n" --proxy http://127.0.0.1:8080 http://93.184.216.34/

# suspicious file extension — 403 (also with a query string after it)
curl -m 10 -o /dev/null -w "code=%{http_code}\n" --proxy http://127.0.0.1:8080 http://example.com/setup.exe
curl -m 10 -o /dev/null -w "code=%{http_code}\n" --proxy http://127.0.0.1:8080 "http://example.com/setup.exe?x=1"
```

Run these one at a time if pasting the whole block doesn't show output —
copy/paste sometimes mangles the quotes.

### 5b. Normalization — encoding tricks don't get past it

```bash
# all 403: separators, case, spaces, double-encoding, full-width unicode letters
for p in "verify_account" "Verify%20Your%20Account" "verify%252Daccount" \
         "%EF%BD%96%EF%BD%85%EF%BD%92%EF%BD%89%EF%BD%86%EF%BD%99-account"; do
  curl -s -o /dev/null -w "%{http_code}  $p\n" --proxy http://127.0.0.1:8080 "http://example.com/$p"
done

# form-encoded body ("+" = space) — 403
curl -s -o /dev/null -w "%{http_code}\n" --proxy http://127.0.0.1:8080 -d "msg=please+confirm+identity+now" http://example.com/submit
```

### 5c. Phishing wording — action word near a target word, any phrasing

```bash
# phrasing that isn't written anywhere in patterns.json — 403 (suspended … account)
curl --proxy http://127.0.0.1:8080 -d "msg=your account has been suspended" http://example.com/submit

# scam phrase — 403
curl -s -o /dev/null -w "%{http_code}\n" --proxy http://127.0.0.1:8080 http://example.com/promo/claim-your-prize

# NOT blocked (404 = forwarded): whole words only, and normal account pages are fine
for p in "reverify-accounts" "news/verification-accountability" "contact-nowhere" "account/reset-password"; do
  curl -s -o /dev/null -w "%{http_code}  $p\n" --proxy http://127.0.0.1:8080 "http://example.com/$p"
done
```

### 5d. Brand impersonation

```bash
# lookalike domain — 403 with "mentions brand 'paypal'" (even though it doesn't resolve)
curl --proxy http://127.0.0.1:8080 http://paypal-secure-login.net/

# shortener subdomain — 403
curl -s -o /dev/null -w "%{http_code}\n" --proxy http://127.0.0.1:8080 http://www.bit.ly/abc
```

`purchase-update.com` (contains "chase") and `login.microsoftonline.com` (real
Microsoft login) are no longer false positives — check directly, since they may not
resolve through the proxy:

```bash
python3 -c "
from inspection.content_inspector import check_content
for d in ['paypal-secure-login.net', 'paypallogin.com', 'purchase-update.com', 'login.microsoftonline.com']:
    print(d, '->', check_content(d, '/')[0])
"
```

### 5e. Attack signatures (path traversal, SQL injection, XSS)

curl and browsers clean up a literal `../` before sending, so use `--path-as-is` or
the encoded form.

```bash
P="--proxy http://127.0.0.1:8080"

# path traversal — 403
curl $P --path-as-is "http://example.com/files/../../../etc/passwd"
curl $P "http://example.com/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# SQL injection in the URL and in a login form body — 403
curl $P "http://example.com/item?id=1%27%20OR%201%3D1--"
curl $P -d "user=admin' or '1'='1&pw=x" http://example.com/login

# cross-site scripting — 403
curl $P "http://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"

# innocent lookalike — 404 (forwarded)
curl -s -o /dev/null -w "%{http_code}\n" $P "http://example.com/search?q=union+station+selected+works"
```

## 6. Malformed / edge-case input

```bash
# empty connection — firewall should just close quietly, no crash
python3 -c "import socket; s=socket.create_connection(('127.0.0.1',8080)); s.close()"

# malformed request line — should get 400, not a crash
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 8080))
s.sendall(b'garbage\r\n\r\n')
print(s.recv(200))
"
```

## 8. Host normalization and parser strictness

```bash
# trailing dot / case / lowercase header name — all 403 (badsite.com)
curl -H "Host: badsite.com." http://127.0.0.1:8080/
curl -H "Host: BadSite.COM." http://127.0.0.1:8080/
curl -H "host: badsite.com" http://127.0.0.1:8080/

# decimal IP (= 93.184.216.34) — 403, IP-literal
curl -H "Host: 1572395042" http://127.0.0.1:8080/

# junk port / missing Host — 400 instead of guessing
curl -H "Host: example.com:abc" http://127.0.0.1:8080/
curl -H "Host:" http://127.0.0.1:8080/

# no space after colon is valid HTTP — 200
curl -H "Host:example.com" http://127.0.0.1:8080/

# space before colon / two Host headers — 400
printf 'GET / HTTP/1.1\r\nHost : example.com\r\n\r\n' | nc -q 3 127.0.0.1 8080
printf 'GET / HTTP/1.1\r\nHost: example.com\r\nHost: badsite.com\r\n\r\n' | nc -q 3 127.0.0.1 8080
```

## 9. CONNECT — the checked destination is the one connected to

```bash
# lying in the Host header doesn't help — 403 (badsite.com is what's checked)
printf 'CONNECT badsite.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n' | nc -q 3 127.0.0.1 8080

# no Host header + forbidden port — 403, port not allowed
printf 'CONNECT example.com:22 HTTP/1.1\r\n\r\n' | nc -q 3 127.0.0.1 8080
```

## 10. Internal destinations (SSRF) and destination IPs

```bash
# proxy forwarding to itself — 403 internal address (used to loop forever)
curl --proxy http://127.0.0.1:8080 http://localhost:8080/

# public domain whose DNS points at 127.0.0.1 — 403, only resolving catches this
curl --proxy http://127.0.0.1:8080 http://localtest.me/

# blocklisted destination IP (blocked_destination_ips) — 403
curl -H "Host: 6.6.6.6" http://127.0.0.1:8080/

# domain that doesn't exist — clean 502
curl --proxy http://127.0.0.1:8080 http://doesnotexist.invalid/
```

To reach a machine on your own LAN (e.g. a lab destination PC), add its IP to
`allowed_internal_destinations` in `rules/blocklist.json`.

## 11. Request reader — complete requests, limits, timeouts

```bash
# keyword after byte 4096 of a body — 403 (the whole body is read and inspected)
curl --proxy http://127.0.0.1:8080 -X POST \
  --data "$(head -c 6000 /dev/zero | tr '\0' a)confirm-identity" http://example.com/submit

# slowloris (1 byte every 2 s) — 408 after ~10 s instead of hanging forever
python3 -c "
import socket, time
s = socket.create_connection(('127.0.0.1', 8080))
try:
    for b in b'GET / HTTP/1.1\r\nHost: example.com\r\n':
        s.sendall(bytes([b])); time.sleep(2)
except OSError: pass
print(s.recv(200))
"

# body claims to be 100 MB — 413 immediately
printf 'POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 99999999\r\n\r\n' | nc -q 3 127.0.0.1 8080

# chunked body — 501
curl --proxy http://127.0.0.1:8080 -H "Transfer-Encoding: chunked" -d "hi" http://example.com/
```

### 11b. Forwarded request is rebuilt correctly

```bash
# binary upload arrives byte-for-byte — prints True
head -c 3000 /dev/urandom > /tmp/random.bin
curl -s --proxy http://127.0.0.1:8080 -H "Content-Type: application/octet-stream" \
  --data-binary @/tmp/random.bin http://httpbin.org/anything \
  | python3 -c "import sys,json,base64; d=json.load(sys.stdin)['data']; print(base64.b64decode(d.split(',',1)[1]) == open('/tmp/random.bin','rb').read())"

# server sees the checked Host and no proxy password
curl -s --proxy http://127.0.0.1:8080 -H "Host: evil.com" \
  -H "Proxy-Authorization: Basic c2VjcmV0" http://httpbin.org/headers
```

## 12. Logging & alerting

After running some of the tests above:

```bash
cat logs/firewall.log                  # every decision, survives restarts
grep "| ALERT" logs/firewall.log       # content-inspection blocks only
grep -c "| BLOCK" logs/firewall.log    # number of blocks
```

## 13. Real browser (Brave)

```bash
# close any existing Brave windows first, then:
brave-browser --proxy-server="127.0.0.1:8080" --user-data-dir=/tmp/brave-firewall-test
```

- `https://example.com` → loads (domain allowed, tunnel opens)
- `https://badsite.com` → browser shows a connection/tunnel error (403 on CONNECT)
- `http://neverssl.com/verify-account` → should get blocked, BUT Brave's
  "Always use secure connections" setting silently upgrades `http://` to `https://`
  by default, which bypasses content inspection entirely (blind tunnel, see
  section 3). Turn that off in Settings → Privacy and Security → Security if you
  want to demo content inspection live in the browser; otherwise use curl
  (section 5) for that part and the browser for tunnel/domain-blocking behavior.
- Body inspection from a real form: open `http://httpbin.org/forms/post`, type
  `confirm-identity` into "Delivery instructions", submit → 403.

Firefox: Settings → Network Settings → Manual proxy configuration → `127.0.0.1`,
port `8080`, tick "Also use this proxy for HTTPS"; and turn off HTTPS-Only Mode
(Privacy & Security) for the same reason as Brave above.
