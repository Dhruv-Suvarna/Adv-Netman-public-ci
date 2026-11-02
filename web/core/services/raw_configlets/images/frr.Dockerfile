# Server-owned sandbox image for the Phase-18 Raw Configlet FRR verifier (adapter ``frr_vtysh_dryrun``).
#
# Built from the ALREADY-LOCAL ubuntu:24.04 base plus the SAME distro FRR package version the live R3/R4 routers run
# (frr 8.4.4-1.1ubuntu6.7), so the syntax check is against the FRR the lab actually uses.  Nothing is run at build time except the
# package install; the image is never started with a network, a mount, a capability, or a secret (see sandbox.oneshot_argv).
#
# Build once, as an explicit operator step (the application NEVER builds or pulls images):
#     docker build -t clab-raw-verifier-frr:8.4.4-1.1ubuntu6.7 -f web/core/services/raw_configlets/images/frr.Dockerfile \
#         web/core/services/raw_configlets/images
#
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends frr=8.4.4-1.1ubuntu6.7 \
 && rm -rf /var/lib/apt/lists/* \
 && chmod 0644 /etc/frr/vtysh.conf
