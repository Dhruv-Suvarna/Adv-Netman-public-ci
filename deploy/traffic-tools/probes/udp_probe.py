"""A bounded UDP probe.  argv: <address> <port> <timeout seconds> <datagrams> <payload bytes>.  Prints one JSON line.

UDP has no handshake, so the probe can only distinguish
    refused              an ICMP port-unreachable came back (nothing is listening)
    open_or_filtered     the datagrams left and nothing objected (a silent listener and a filter look identical)
A measured UDP delivery test is the iperf3 UDP family, which has a receiver.  Baked into the tools image.
"""
import json
import socket
import sys
import time

host, port, timeout, count, size = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM)
s.settimeout(timeout)
sent = replies = 0
result = "open_or_filtered"
t = time.monotonic()
try:
    s.connect((host, port))
    for _ in range(count):
        try:
            s.send(b"\x00" * size)
            sent += 1
            try:
                s.recv(2048)
                replies += 1
            except socket.timeout:
                pass
        except ConnectionRefusedError:
            result = "refused"
            break
        except OSError:
            result = "unreachable"
            break
except OSError:
    result = "unreachable"
finally:
    s.close()
print(json.dumps({"result": result, "sent": sent, "replies": replies, "elapsed_ms": round((time.monotonic() - t) * 1000, 3)}))
