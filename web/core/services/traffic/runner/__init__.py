"""The NMAS traffic runner: a small host-side broker that runs ONE bounded diagnostic inside a lab endpoint's network namespace.

    Django (unprivileged, NoNewPrivileges)  --Unix socket-->  traffic runner  --docker-->  pinned tools image  --netns-->  endpoint

The website holds no runtime privilege for traffic tests; this service holds exactly the container-runtime access it needs and offers no
general command interface.  A request is a closed, structured document (endpoint IDS, an address family, a test type, bounded integers);
everything that reaches the runtime -- container identity, image, binary, flags, addresses -- is derived HERE from the runner's own
root-owned configuration and its own limits (``policy``), whatever the website already validated.

This package is deliberately self-contained: standard library only and relative imports only, because the installer copies it to a
root-owned directory (``/usr/local/lib/nmas-traffic-runner/nmas_traffic_runner``) so the website's account cannot alter the code that
holds the privilege.  Modules:

    policy   the runner's own limits and the strict request schema (validation layer two)
    config   the root-owned catalogue: lab, endpoint id -> container, tools image id, allowed peer uids
    runtime  THE one process boundary of the traffic subsystem (every container-runtime call)
    engine   one run: resolve, discover addresses, execute, clean up exactly what the run created
    server   the Unix-socket front end: peer-credential check, bounded read, audit log line
"""

PROTOCOL_VERSION = 1
RUNNER_VERSION = "traffic-runner-1"
