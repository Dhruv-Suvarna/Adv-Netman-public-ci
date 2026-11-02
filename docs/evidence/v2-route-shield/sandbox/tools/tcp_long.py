"""One long-lived TCP session: a numbered line every 100 ms, each must be echoed.  usage: tcp_long.py <dst> <log>
Log lines:  OPEN t | STALL t gap_ms seq | STAT t sent echoed | DEAD t reason | CLOSE t sent echoed max_gap_ms"""
import signal, socket, sys, time
dst, log = sys.argv[1], open(sys.argv[2], "a", buffering=1)
stop = False
def bye(*_):
    global stop; stop = True
signal.signal(signal.SIGTERM, bye)
s = socket.create_connection((dst, 7001), timeout=5); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.settimeout(0.02)
log.write(f"OPEN {time.time():.3f} {s.getsockname()[0]}\n")
sent = echoed = 0; buf = b""; last = time.time(); worst = 0.0; stat = time.time(); stalled = False
try:
    while not stop:
        s.sendall(b"%010d\n" % sent); sent += 1
        try:
            data = s.recv(65536)
            if not data: raise ConnectionError("peer closed")
            buf += data; n = buf.count(b"\n")
            if n:
                echoed += n; buf = buf[buf.rfind(b"\n") + 1:]; now = time.time(); gap = now - last
                if gap > 0.25: log.write(f"STALL {now:.3f} {gap * 1000:.0f} {echoed}\n")
                worst = max(worst, gap); last = now
        except socket.timeout:
            pass
        now = time.time()
        if now - last > 20: raise TimeoutError("no echo for 20 s")
        if now - stat >= 10: log.write(f"STAT {now:.3f} {sent} {echoed}\n"); stat = now
        time.sleep(max(0.0, 0.1 - (time.time() - now)))
    # drain what is still in flight
    s.settimeout(2.0)
    while echoed < sent:
        data = s.recv(65536)
        if not data: raise ConnectionError("peer closed during drain")
        echoed += data.count(b"\n")
    log.write(f"CLOSE {time.time():.3f} {sent} {echoed} {worst * 1000:.0f}\n")
except Exception as exc:
    log.write(f"DEAD {time.time():.3f} {type(exc).__name__}: {exc} sent={sent} echoed={echoed}\n"); sys.exit(1)
