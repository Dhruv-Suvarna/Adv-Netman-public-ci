"""Web host of the sandbox: a TCP echo service (7001) and a minimal HTTP service (80), both dual-stack."""
import asyncio, socket
async def echo(r, w):
    try:
        while data := await r.read(65536):
            w.write(data); await w.drain()
    except Exception: pass
    finally: w.close()
BODY = b"nmas-sandbox-web\n"
async def http(r, w):
    try:
        await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        w.write(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(BODY) + BODY); await w.drain()
    except Exception: pass
    finally: w.close()
def sock(port):
    s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(("::", port)); s.listen(512); return s
async def main():
    a = await asyncio.start_server(echo, sock=sock(7001)); b = await asyncio.start_server(http, sock=sock(80))
    async with a, b: await asyncio.gather(a.serve_forever(), b.serve_forever())
asyncio.run(main())
