
## pipeline
```
[Client PC] → sends request to Firewall PC (configured as proxy)
       ↓
[Firewall PC]
   1. Packet/Connection Interceptor — accepts incoming socket connection
   2. Parser — reads raw bytes, extracts src/dst IP, port, protocol, 
      and (once buffered) HTTP request line + headers (Host, path, etc.)
   3. Stateless Rule Engine — static IP/port/protocol allow-deny checks
   4. Connection State Tracker — TCP-session-level state validity check
   5. Content Inspection Engine — checks reassembled HTTP request against 
      suspicious patterns (blocklisted domains, URL shorteners, IP-literal 
      URLs, phishing-like keyword combos); scoring system optional 
      (e.g. score >= threshold = block)
   6. Decision — ALLOW (forward to destination, relay response back) or DROP
   7. Logger — timestamp, src/dst, verdict, reason; flags suspicious 
      activity distinctly (alerting)
       ↓
[Destination PC] — only receives requests that passed all checks
```

## basic components
full layered stack, not just content filtering:

Packet Filtering (Network/Datalink layer) — IP/port/protocol rules
Stateful Inspection (Transport layer) — TCP session/connection tracking
Deep Packet Inspection (Application layer) — URL/content checks
Logging & Alerting
Policy Enforcement (rule-based, blacklist/whitelist/regex)
Extensibility (pluggable design for new protocols/rules)

Since HTTP requests can span multiple TCP packets, true per-packet content inspection (raw Scapy/libpcap style) can't reliably see complete URLs/headers. The correct approach (Option B, matching what the teacher's demo actually requires) is: accept the connection, buffer/reassemble bytes until a complete HTTP request is received, THEN run content inspection on the full reassembled request — not inspect raw packets one-by-one. "Packet Interceptor" and "Parser" in practice mean "accept connection, buffer until complete request," not literal per-packet Scapy sniffing. Cheap checks (rule engine, connection state) should run before the expensive content-inspection step, to reject junk early.


## What's Custom-Built vs. Library-Provided
 
**Custom-built (Anoushka writes this logic herself):**
1. Proxy server — socket-based server accepting client connections, parsing raw HTTP text, forwarding to real destination, relaying response back
2. Stateless Rule Engine — IP/port/protocol allow-deny list + matching logic
3. Connection State Tracker — state table (dict keyed by src/dst ip+port) tracking connection lifecycle
4. Content Inspection Engine — blocklist matching + regex-based suspicious pattern detection (shorteners, IP-literal URLs, phishing keyword combos), with an optional scoring/threshold system
5. Logger + Alerter — structured logging of every decision with reason; suspicious activity flagged distinctly
**NOT built from scratch (libraries handle this):**
- Raw socket creation/management → Python's built-in `socket` module
- HTTP protocol semantics → hand-parsed as plain text, or `http.client`/`email.parser` for headers
- Pattern matching → built-in `re` (regex)
- Logging → built-in `logging` module
- (Scapy/NetfilterQueue/libpcap were relevant to the earlier V1 raw-packet-interception scope but are NOT needed now that the architecture is proxy/socket-based)
## Libraries Required (current, final scope)
- Python `socket` — client↔firewall↔destination relaying
- Python `re` — pattern/URL matching
- Python `logging` — structured logs
- Plain text/JSON file — blocklist storage (no DB needed)
- Optional stretch: `flask` for a live log/alert dashboard during demo