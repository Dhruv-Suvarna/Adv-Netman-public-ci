"""Native ZTP from the shell -- the automation side of Phase 3 (the website carries the operator side).

    nmas_ztp adapters                                              READ-ONLY: every native adapter's capability / evidence
    nmas_ztp network-create --name N --prefix P --gateway G --pool-start A --pool-end B --service-prefix S --service-address X
                            --relay RELAY_IP=UPSTREAM [--relay ...] --config-root DIR [--lease-file F] [--provider ISC_DHCP|KEA] --actor U
                            (DIR must lie under the NMAS_ZTP_PROVIDER_ROOTS setting)
    nmas_ztp session-open --device DEV-x --auth BAUTH-x --network N --actor U
    nmas_ztp dhcp-validate | dhcp-apply | dhcp-rollback --network N --actor U      isolated provider only
    nmas_ztp ingest --network N [--follow SECONDS]                 the provider's own lease database -> observations
    nmas_ztp serve --network N [--no-tftp] [--follow-ingest SECONDS] read-only HTTP (+ TFTP) delivery on the service address
    nmas_ztp contact --session ZTP-x --actor U                     SSH key exchange only (first-seen host key, untrusted)
    nmas_ztp enroll-host-key --session ZTP-x --fingerprint SHA256:... --basis TEXT --actor U   (approver; out-of-band value)
    nmas_ztp verify --session ZTP-x --actor U                      authenticated, host-key-pinned verification -> BOOTSTRAPPED
    nmas_ztp status --session ZTP-x                                READ-ONLY: every evidence stage as JSON
    nmas_ztp expire                                                expire artifacts and authorizations whose window is over

Operator actions require ``--actor`` to be an active website user holding the same permission as the page.  Nothing here
touches a production DHCP service, VLAN 200, NetBox or a production device; production admission does not exist here.
"""

from __future__ import annotations

import json
import time

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from ... import models
from ...services.devices import authorization, lifecycle
from ...services.identity.policy import Action, permission_name
from ...services.ztp import adapters, artifacts, discovery, policy, servers, workflow

PERMISSION = {"network-create": Action.APPROVE, "session-open": Action.EDIT, "dhcp-validate": Action.VALIDATE, "dhcp-apply": Action.EXECUTE,
              "dhcp-rollback": Action.EXECUTE, "contact": Action.VALIDATE, "enroll-host-key": Action.APPROVE, "verify": Action.EXECUTE}


class Command(BaseCommand):
    help = "Native ZTP: bootstrap networks, sessions, isolated DHCP policy, lease ingestion, delivery servers and verification."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("adapters")
        net = sub.add_parser("network-create")
        for flag in ("--name", "--prefix", "--gateway", "--pool-start", "--pool-end", "--service-prefix", "--service-address", "--config-root"):
            net.add_argument(flag, required=True)
        net.add_argument("--relay", action="append", required=True, help="RELAY_IP=UPSTREAM_DEVICE")
        net.add_argument("--lease-file", default="")
        net.add_argument("--provider", default="ISC_DHCP", choices=models.DhcpProviderKind.values)
        net.add_argument("--http-port", type=int, default=8080)
        net.add_argument("--vlan", default="")
        opened = sub.add_parser("session-open")
        opened.add_argument("--device", required=True)
        opened.add_argument("--auth", required=True)
        opened.add_argument("--network", required=True)
        for name in ("dhcp-validate", "dhcp-apply", "dhcp-rollback"):
            sub.add_parser(name).add_argument("--network", required=True)
        ingest = sub.add_parser("ingest")
        ingest.add_argument("--network", required=True)
        ingest.add_argument("--follow", type=int, default=0)
        serve = sub.add_parser("serve")
        serve.add_argument("--network", required=True)
        serve.add_argument("--no-tftp", action="store_true")
        serve.add_argument("--follow-ingest", type=int, default=0)
        for name in ("contact", "verify", "status"):
            sub.add_parser(name).add_argument("--session", required=True)
        enroll = sub.add_parser("enroll-host-key")
        enroll.add_argument("--session", required=True)
        enroll.add_argument("--fingerprint", required=True)
        enroll.add_argument("--basis", required=True)
        sub.add_parser("expire")
        for name, child in sub.choices.items():
            if name in PERMISSION:
                child.add_argument("--actor", required=True)

    def _actor(self, options) -> str:
        user = get_user_model().objects.filter(username=options["actor"], is_active=True).first()
        required = PERMISSION[options["action"]]
        if user is None or not user.has_perm(permission_name(required)):
            raise CommandError(f"--actor must be an active user holding core.{required.value}")
        return user.get_username()

    def _network(self, name):
        network = models.BootstrapNetwork.objects.filter(name=name, state=models.BootstrapNetworkState.ACTIVE).first()
        if network is None:
            raise CommandError("unknown or retired bootstrap network")
        return network

    def _session(self, session_id):
        session = workflow.get_session(session_id)
        if session is None:
            raise CommandError("unknown ZTP session")
        return session

    def _out(self, payload):
        self.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str))

    def _result(self, result):
        if not result.ok:
            raise CommandError(f"refused: {', '.join(result.codes) or 'unknown'}")
        self.stdout.write(f"{result.action}: {result.session.session_id if result.session else ''} OK")

    def handle(self, *args, **options):  # noqa: C901 - a flat dispatcher
        action = options["action"]
        actor = self._actor(options) if action in PERMISSION else ""
        if action == "adapters":
            return self._out(adapters.capability_report())
        if action == "network-create":
            relays = []
            for item in options["relay"]:
                address, _, upstream = item.partition("=")
                relays.append({"relay_address": address, "upstream_device": upstream})
            row, problems = policy.create_network(
                actor=actor, name=options["name"], ipv4_prefix=options["prefix"], gateway=options["gateway"], pool_start=options["pool_start"],
                pool_end=options["pool_end"], service_prefix=options["service_prefix"], service_address=options["service_address"],
                trusted_relays=relays, config_root=options["config_root"], lease_file=options["lease_file"], provider=options["provider"],
                http_port=options["http_port"], vlan=options["vlan"] or None)
            if problems:
                raise CommandError(f"refused: {json.dumps(problems)}")
            return self.stdout.write(f"bootstrap network {row.name} recorded")
        if action == "session-open":
            device = lifecycle.get_device(options["device"])
            if device is None:
                raise CommandError("unknown device")
            return self._result(workflow.open_session(device, authorization=authorization.get_authorization(options["auth"]),
                                                      network=self._network(options["network"]), actor=actor))
        if action in ("dhcp-validate", "dhcp-apply", "dhcp-rollback"):
            function = {"dhcp-validate": policy.validate_policy, "dhcp-apply": policy.apply_policy, "dhcp-rollback": policy.rollback_policy}[action]
            row, problems = function(self._network(options["network"]), actor=actor)
            if problems:
                raise CommandError(f"refused: {json.dumps(problems)}")
            return self._out({"application": row.pk, "state": row.state, "sha256": row.config_sha256, "sessions": row.sessions,
                              "validation": row.validation, "read_back": row.read_back})
        if action == "ingest":
            network = self._network(options["network"])
            while True:
                self._out(discovery.ingest(network))
                if not options["follow"]:
                    return None
                time.sleep(options["follow"])
        if action == "serve":
            return self._serve(self._network(options["network"]), tftp=not options["no_tftp"], follow=options["follow_ingest"])
        if action == "contact":
            return self._result(workflow.contact_management(self._session(options["session"]), actor=actor))
        if action == "enroll-host-key":
            return self._result(workflow.enroll_host_key(self._session(options["session"]), fingerprint=options["fingerprint"],
                                                         actor=actor, basis=options["basis"]))
        if action == "verify":
            result = workflow.verify_management(self._session(options["session"]), actor=actor)
            if not result.ok:
                self._out(result.detail)
            return self._result(result)
        if action == "status":
            return self._out(workflow.status(self._session(options["session"])))
        expired = artifacts.expire_due()
        auths = authorization.expire_due()
        return self.stdout.write(f"expired artifacts {expired}; authorizations {', '.join(auths) or '-'}")

    def _serve(self, network, *, tftp: bool, follow: int):
        """Run the delivery servers on the network's service address (blocks).  Optionally fold leases every ``follow`` s."""
        artifacts.expire_due()                      # restart recovery: close what expired while the service was down
        http_server = servers.make_http_server(network.service_address, network.http_port)
        servers.serve_forever_in_thread(http_server)
        self.stdout.write(f"HTTP bootstrap delivery on {network.service_address}:{network.http_port}")
        if tftp:
            tftp_server = servers.make_tftp_server(network.service_address, network.tftp_port)
            servers.serve_forever_in_thread(tftp_server)
            self.stdout.write(f"TFTP bootstrap delivery on {network.service_address}:{network.tftp_port}")
        self.stdout.flush()
        try:
            while True:
                if follow:
                    summary = discovery.ingest(network)
                    if summary["new"]:
                        self.stdout.write(json.dumps(summary, sort_keys=True))
                        self.stdout.flush()
                time.sleep(follow or 3600)
        except KeyboardInterrupt:
            http_server.shutdown()
