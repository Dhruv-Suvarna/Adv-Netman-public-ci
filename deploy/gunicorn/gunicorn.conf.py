"""Gunicorn configuration for the NMAS website (V2 Phase 1).  No secrets: the environment comes from the systemd unit.

Bound to loopback only -- Apache is the sole client.  The timeout is long because a few operator actions (execution,
deep health, verification sandbox) legitimately run synchronously for minutes; they are bounded by their own
server-side timeouts.
"""

import os

bind = os.environ.get("NMAS_GUNICORN_BIND", "127.0.0.1:8002")
workers = int(os.environ.get("NMAS_GUNICORN_WORKERS", "3"))
threads = int(os.environ.get("NMAS_GUNICORN_THREADS", "2"))
worker_class = "gthread"
timeout = int(os.environ.get("NMAS_GUNICORN_TIMEOUT", "900"))
graceful_timeout = 60
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
forwarded_allow_ips = "127.0.0.1,::1"
proxy_allow_ips = "127.0.0.1,::1"
accesslog = "-"
errorlog = "-"
loglevel = "info"
# Request line only (no query string -- it can carry filter values) and the correlation id; never cookies or headers.
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(b)s %(L)ss rid=%({x-request-id}o)s'
capture_output = True
