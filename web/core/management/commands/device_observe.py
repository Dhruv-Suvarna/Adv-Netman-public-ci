"""Explicit, operator-invoked capture of ONE governed read-only version observation (see docs/troubleshooting/observation-runner.md).

Composes trusted_sources(), observation_authorizations.admit(), connection_factory(), session_provider() and collect().
Everything is explicit on the command line (device, source id, authorization id, operator, evidence directory); every
prerequisite -- including the authorization's device scope, command scope, expiry, use budget and operator independence -- is
checked before any connection is attempted, and the authorization is re-checked immediately before ingest.
Source keys come only from the environment through ``trusted_sources()`` and are never accepted as arguments or printed.
No identity verification, admission or deployment is performed; local evidence is not gateway attestation.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from core.services.devices import (observation_authorizations, observation_collector, observation_connections, observation_evidence,
                                   observation_sessions, observations, resolver)


class Command(BaseCommand):
    help = ("Capture one read-only NOS version observation for a managed device under an approved observation authorization "
            "(OBSAUTH-NNNNNN) into a local evidence directory (no identity approval, no admission).")

    def add_arguments(self, parser):
        parser.add_argument("--device", required=True)
        parser.add_argument("--source", required=True, help="registered observation source id (key is read from its environment variable)")
        parser.add_argument("--authorization-ref", required=True, dest="authorization_ref",
                            help="approved observation authorization, OBSAUTH-NNNNNN#sha256=<scope digest> (see observation_authorize)")
        parser.add_argument("--operator", required=True, help="NMAS account (EXECUTE permission) running the observation; not the approver")
        parser.add_argument("--evidence-dir", required=True, dest="evidence_dir")

    # seams for tests; production defaults compose the existing governed pieces
    def build_connection_factory(self):
        return observation_connections.connection_factory()

    def handle(self, *args, **opts):
        device, source_id = str(opts["device"]).strip(), str(opts["source"]).strip()
        auth_ref, operator = str(opts["authorization_ref"]).strip(), str(opts["operator"]).strip()
        if not device or not source_id or not auth_ref or not operator:
            raise CommandError("device, source, authorization reference and operator must be non-empty")
        sources = observations.trusted_sources()
        if source_id not in sources:
            raise CommandError("SOURCE_UNCONFIGURED: source is not registered or its key is not available; nothing was contacted")
        try:
            sink = observation_evidence.LocalEvidenceSink(opts["evidence_dir"])
        except observation_evidence.EvidenceError as exc:
            raise CommandError(f"{exc.code}: evidence directory refused; nothing was contacted") from None
        target = resolver.resolve(device)
        if target is None:
            raise CommandError("TARGET_UNKNOWN: device is not in the authoritative inventory; nothing was contacted")
        if target.scope not in resolver.WRITABLE_SCOPES:
            raise CommandError("TARGET_NOT_MANAGEABLE: device is read-only, excluded or not yet reachable; nothing was contacted")
        spec = observations.SPECS.get(target.platform)
        if spec is None:
            raise CommandError("PLATFORM_UNSUPPORTED: no observation command exists for this platform; nothing was contacted")
        admitted = observation_authorizations.admit(auth_ref, device=target.name, platform=target.platform, command=spec.command,
                                                    operator=operator)
        if not admitted.ok:
            raise CommandError(f"{'; '.join(admitted.codes)}: observation not authorized; nothing was contacted")
        authorization, use = admitted.authorization, admitted.use

        provider = observation_sessions.session_provider(self.build_connection_factory(),
                                                         observation_authorizations.reference(authorization))
        try:
            result = observation_collector.collect(
                target.name, source_id=source_id, sources=sources, session_provider=provider, evidence_sink=sink,
                pre_ingest_guard=lambda: observation_authorizations.still_valid(authorization))
        except Exception:  # noqa: BLE001 - the reserved use must still be closed; detail may contain connection parameters
            observation_authorizations.finish(use, ok=False, codes=["COLLECTOR_ERROR"])
            raise CommandError("observation refused: COLLECTOR_ERROR") from None
        row = result.record
        observation_authorizations.finish(use, ok=result.ok, codes=result.codes, nonce=getattr(row, "nonce", ""),
                                          evidence_ref=result.evidence_ref, record=row)
        if not result.ok:
            detail = "; ".join(result.codes) or "unknown"
            refusal = getattr(provider, "last_refusal", "")
            raise CommandError(f"observation refused: {detail}" + (f" (session: {refusal})" if refusal else ""))
        self.stdout.write(f"observed {target.name}: version={getattr(row, 'version', '')} evidence_ref={result.evidence_ref} "
                          f"authorization={authorization.auth_id} (local, unattested; identity NOT verified, device NOT admitted)")
