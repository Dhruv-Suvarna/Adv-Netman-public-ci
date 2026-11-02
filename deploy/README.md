# NMAS website hosting (V2 Phase 1)

Repository-owned, secret-free templates for persistently hosting the NMAS Django site:

```
browser (local)      --> Apache 127.0.0.1:80   (vhost "local", sets X-Forwarded-Proto: http)  --+
Cloudflare Tunnel    --> Apache 127.0.0.1:8081 (vhost "tunnel", sets X-Forwarded-Proto: https) --+--> Gunicorn 127.0.0.1:8002 --> Django
```

* `gunicorn/gunicorn.conf.py`      Gunicorn settings (loopback bind only).
* `systemd/nmas-web.service`       Gunicorn unit (autostart, restart on failure); reads `/etc/nmas/nmas-web.env`.
* `apache/nmas.conf`               Apache reverse proxy + `/static/` alias (rendered with the deploy root).
* `cloudflared/config.yml.example` Website-only tunnel ingress (hostname -> Apache tunnel vhost; everything else 404).
* `cloudflared/cloudflared-nmas.service` systemd unit for the named tunnel.
* `env/nmas-web.env.example`       The runtime environment keys (placeholders only).
* `scripts/install_web_stack.sh`   Idempotent installer for Apache + Gunicorn (creates the protected env file with a
                                   freshly generated SECRET_KEY that is never printed).
* `scripts/install_cloudflared.sh` Installs the cloudflared package and the tunnel unit; account authorization stays
                                   an explicit operator step.

Nothing here contains a secret.  Runtime secrets live only in `/etc/nmas/nmas-web.env` (root:student, 0640) and
`/etc/cloudflared/` (tunnel credentials, root only).  See docs/V2_PHASE1_IDENTITY_SECURITY_AUDIT.md.

## Traffic runner (V2 Phase 5B)

`systemd/nmas-traffic-runner.socket` + `.service`, `traffic-tools/` (the pinned diagnostic tools image) and
`scripts/install_traffic_runner.sh`. The runner is a separate, sandboxed service that the website reaches over a local Unix socket;
`nmas-web.service` is not changed and keeps `NoNewPrivileges`. Install only after the deployment checkout has been promoted:

    sudo deploy/scripts/install_traffic_runner.sh --deploy-root <deployment checkout>
    deploy/scripts/install_traffic_runner.sh --deploy-root <checkout> --render-only <dir>     # renders the units, installs nothing

See `docs/V2_PHASE5_PROVISIONING_TRAFFIC_SOAK.md` §6.
