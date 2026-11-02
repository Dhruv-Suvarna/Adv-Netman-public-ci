"""Entry point of the traffic runner service.

    python3 -m nmas_traffic_runner --config /etc/nmas/traffic-runner.json                  # socket passed by systemd (socket activation)
    python3 -m nmas_traffic_runner --config <file> --socket <path>                         # development: binds <path> itself, mode 0660
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
import threading
import time

from . import RUNNER_VERSION, config, engine, server

SD_LISTEN_FDS_START = 3


def _log(record: dict) -> None:
    sys.stdout.write(json.dumps({"ts": round(time.time(), 3), **record}, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


def _listener(path: str | None) -> socket.socket:
    if path:
        if os.path.lexists(path):
            os.unlink(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        previous = os.umask(0o117)
        try:
            listener.bind(path)
        finally:
            os.umask(previous)
        listener.listen(8)
        return listener
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise SystemExit("no socket: start through nmas-traffic-runner.socket or pass --socket")
    listener = socket.socket(fileno=SD_LISTEN_FDS_START)
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM:
        raise SystemExit("the inherited socket is not a Unix stream socket")
    return listener


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="nmas_traffic_runner", description="NMAS traffic runner")
    parser.add_argument("--config", required=True)
    parser.add_argument("--socket", default=None)
    options = parser.parse_args(argv)
    try:
        settings = config.load(options.config)
    except config.ConfigError as exc:
        _log({"event": "startup_refused", "reason": str(exc)})
        return 2
    listener = _listener(options.socket)
    broker = engine.Engine(settings, log=_log)
    stop = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    _log({"event": "started", "runner": RUNNER_VERSION, "instance": settings.instance, "lab": settings.lab, "endpoints": sorted(settings.endpoints),
          "tools_image": settings.tools_image, "abandoned_removed": len(broker.reconcile())})
    server.serve(listener, broker, settings.allowed_peer_uids, _log, stop=stop)
    _log({"event": "stopped"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
