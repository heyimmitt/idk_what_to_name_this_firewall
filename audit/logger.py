import logging
import os
from logging.handlers import RotatingFileHandler

# logs/ sits in the project root, next to main.py
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "firewall.log")
LOG_LEVEL = logging.INFO   # set to logging.DEBUG to also see parsed requests/headers

# custom level for content-inspection blocks, so "this looked MALICIOUS" stands out
# from "this just isn't allowed". 35 sits between WARNING (30) and ERROR (40)
ALERT = 35
logging.addLevelName(ALERT, "ALERT")

logger = logging.getLogger("firewall")

# call once at startup: every log line goes to both the log file and the terminal
def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s", "%Y-%m-%d %H:%M:%S")

    # rotating: at 1 MB the file is renamed to firewall.log.1 (keeping 3 old ones),
    # so the log can never grow until it fills the disk
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    console_handler = logging.StreamHandler()

    for handler in (file_handler, console_handler):
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(LOG_LEVEL)

# one line per decision, always the same fields in the same order:
#   client | request | verdict | stage that decided | reason
# verdict is ALLOW / BLOCK (policy said no) / REJECT (malformed, too slow, too big)
# / ERROR (destination unreachable, or a bug in our code)
def log_decision(client_addr, request, verdict, stage, reason):
    if verdict == "ALLOW":
        level = logging.INFO
    elif verdict == "ERROR":
        level = logging.ERROR
    elif stage == "content":
        level = ALERT          # looked malicious -- flagged distinctly
    else:
        level = logging.WARNING
    client = f"{client_addr[0]}:{client_addr[1]}"
    logger.log(level, f"{client} | {request} | {verdict} | {stage} | {reason}")
