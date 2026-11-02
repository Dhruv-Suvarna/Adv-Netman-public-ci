"""A NEW TCP connection + HTTP GET every 250 ms.  usage: http_loop.py <dst> <log>
Log lines:  FAIL t reason | SLOW t ms | STAT t ok fail slow | CLOSE t ok fail slow max_ms"""
import signal, socket, sys, time
dst, log = sys.argv[1], open(sys.argv[2], "a", buffering=1)
stop = False
def bye(*_):
    global stop; stop = True
signal.signal(signal.SIGTERM, bye)
ok = fail = slow = 0; worst = 0.0; stat = time.time()
while not stop:
    t = time.time()
    try:
        s = socket.create_connection((dst, 80), timeout=4); s.settimeout(4)
        s.sendall(b"GET / HTTP/1.0\r\nHost: web\r\n\r\n"); data = b""
        while chunk := s.recv(4096): data += chunk
        s.close()
        if not data.startswith(b"HTTP/1.0 200") or not data.endswith(b"nmas-sandbox-web\n"): raise ValueError("bad reply")
        ms = (time.time() - t) * 1000; ok += 1; worst = max(worst, ms)
        if ms > 400: slow += 1; log.write(f"SLOW {t:.3f} {ms:.0f}\n")       # a retransmitted SYN or segment: a packet was lost
    except Exception as exc:
        fail += 1; log.write(f"FAIL {t:.3f} {type(exc).__name__}: {exc}\n")
    now = time.time()
    if now - stat >= 10: log.write(f"STAT {now:.3f} {ok} {fail} {slow}\n"); stat = now
    time.sleep(max(0.0, 0.25 - (now - t)))
log.write(f"CLOSE {time.time():.3f} {ok} {fail} {slow} {worst:.0f}\n")
