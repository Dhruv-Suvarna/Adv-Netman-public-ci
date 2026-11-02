"""One bounded TCP connect attempt.  argv: <address> <port> <timeout seconds>.  Prints one JSON line.  Baked into the tools image."""
import json
import socket
import sys
import time

host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM)
s.settimeout(timeout)
t = time.monotonic()
try:
    s.connect((host, port))
    result = "connected"
except ConnectionRefusedError:
    result = "refused"
except socket.timeout:
    result = "timeout"
except OSError:
    result = "unreachable"
finally:
    s.close()
print(json.dumps({"result": result, "elapsed_ms": round((time.monotonic() - t) * 1000, 3)}))
