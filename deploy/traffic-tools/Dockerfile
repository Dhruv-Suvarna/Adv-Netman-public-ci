# NMAS traffic tools image (V2 Phase 5B): the ONLY software the traffic runner ever executes inside an endpoint's network namespace.
#
# Built by deploy/scripts/install_traffic_runner.sh; the runner then starts it BY IMAGE ID (sha256:...), never by a mutable tag.
# Contents are limited to the diagnostics the workbench offers:
#   iputils-ping (ping, IPv4 + IPv6) · traceroute · iperf3 · iproute2-minimal (`ip -j addr`, address discovery) · python3 (the two
#   fixed socket probes below).  No shell tooling is added, nothing is taken from a NOS image, and nothing is installed into H1-H4 /
#   WebServer: the image only JOINS an endpoint's network namespace.
# Base and packages are pinned; bump them deliberately and re-run the live traffic matrix.
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache \
      iputils-ping=20250605-r2 \
      traceroute=2.1.6-r0 \
      iperf3=3.20-r0 \
      iproute2-minimal=7.0.0-r0 \
      python3=3.14.8-r0
COPY probes/tcp_connect.py probes/udp_probe.py /opt/nmas-traffic/
LABEL org.opencontainers.image.title="nmas-traffic-tools" \
      org.opencontainers.image.description="NMAS traffic workbench diagnostics: ping, traceroute, iperf3, ip, two fixed socket probes"
# The runner always sets an explicit entrypoint and user; a bare `docker run` of this image does nothing.
USER 65534:65534
ENTRYPOINT ["/bin/false"]
