# Application-Layer Firewall

A proxy-based firewall. Sits between a client and the destination server, inspects each request, and decides whether to allow or block it.

## Architecture

```
[Client] → [Firewall Proxy] → [Destination]
```


## Pipeline
```
[Client PC] → sends request to Firewall PC (configured as proxy)
       ↓
[Firewall PC]
   1. Packet/Connection Interceptor — accepts incoming socket connection
   2. Parser — reads raw bytes, extracts src/dst IP, port, protocol, 
      and (once buffered) HTTP request line + headers (Host, path, etc.)
   3. Stateless Rule Engine — static IP/port/protocol allow-deny checks
   4. Connection State Tracker — TCP-session-level state validity check - planned
   5. Content Inspection Engine — checks reassembled HTTP request against - planned 
      suspicious patterns (blocklisted domains, URL shorteners, IP-literal 
      URLs, phishing-like keyword combos); scoring system optional 
      (e.g. score >= threshold = block)
   6. Decision — ALLOW (forward to destination, relay response back) or DROP
   7. Logger — timestamp, src/dst, verdict, reason; flags suspicious - planned
      activity distinctly (alerting)
       ↓
[Destination PC] — only receives requests that passed all checks
```

## Project structure

```
main.py                    # entry point
config.py                  # HOST, PORT, constants
proxy/
  interceptor.py           # listening socket, accept loop, per-connection handling
  http_parser.py           # parses request line + headers
rules/
  stateless_rules.py       # IP/domain allow-deny matching
```

## Running it

```bash
python3 main.py
```

In another terminal:

```bash
curl http://127.0.0.1:8080/                        # allowed
curl -H "Host: badsite.com" http://127.0.0.1:8080/  # blocked by rule
```

## Status

Interceptor, parser, and stateless rule engine are working. The proxy currently replies with a placeholder message rather than forwarding to a real destination — that's next, along with support for real browser-proxy requests and HTTPS.
