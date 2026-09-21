import threading
import time

MAX_CONCURRENT_PER_IP = 20     # how many connections one client can have open at once
MAX_NEW_CONNECTIONS_PER_WINDOW = 30   # how many NEW connections one client can open...
RATE_WINDOW_SECONDS = 10              # ...within this many seconds
# arbitrarily picked, change as per tuning with real traffic data

lock = threading.Lock()   # guards the two dicts below, since threads share them
active_connections = {}      # client_ip -> count of connections currently open
connection_timestamps = {}   # client_ip -> list of times a new connection was accepted

# call once per new connection, right after accept(). Returns (allowed, reason).
def register_connection(client_ip):
    now = time.time()
    with lock:
        timestamps = connection_timestamps.setdefault(client_ip, [])
        timestamps[:] = [t for t in timestamps if now - t < RATE_WINDOW_SECONDS]  # drop old entries

        if len(timestamps) >= MAX_NEW_CONNECTIONS_PER_WINDOW:
            return False, f"{client_ip} opened {len(timestamps)} connections in {RATE_WINDOW_SECONDS}s (rate limit)"

        if active_connections.get(client_ip, 0) >= MAX_CONCURRENT_PER_IP:
            return False, f"{client_ip} has {active_connections[client_ip]} connections open already (concurrency limit)"

        timestamps.append(now)
        active_connections[client_ip] = active_connections.get(client_ip, 0) + 1
        return True, "ok"

# call once when a connection is done (in a finally, so it always runs)
def release_connection(client_ip):
    with lock:
        if client_ip in active_connections:
            active_connections[client_ip] -= 1
            if active_connections[client_ip] <= 0:
                del active_connections[client_ip]
