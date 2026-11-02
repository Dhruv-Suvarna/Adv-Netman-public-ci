"""Reproducible, non-destructive capability verification and evidence recording."""

from __future__ import annotations

import subprocess
import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from core.services.capabilities import evidence, features
from core.services.capabilities.axes import Axis, EvidenceStatus, EvidenceType


def _head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=settings.REPO_ROOT,
            capture_output=True, check=True, text=True, timeout=5,
        ).stdout.strip()[:40]
    except (OSError, subprocess.SubprocessError):
        return ""


def verify_non_destructive(platform: str, feature_key: str, test_type: EvidenceType) -> tuple[bool, str]:
    from core.services.capabilities.offline_verify import verify_cell

    cell = verify_cell(platform, features.by_key()[feature_key], head=_head())
    failures = [f"{name}: {result['reason']} — {result['detail']}" for name, result in cell.probes.items()
                if result["outcome"] in {"FAIL", "BLOCKED"}]
    return not failures, "; ".join(failures) if failures else f"Actual offline fixture probes passed for {feature_key}; live stages remain outstanding."


class Command(BaseCommand):
    help = "Exercise real offline application paths and persist an exhaustive per-cell probe ledger."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=("verify", "verify-matrix", "verify-isolated", "verify-isolated-srl",
                                               "verify-isolated-vendor", "verify-isolated-ceos-ospf", "verify-isolated-ceos-ospf3",
                                               "verify-isolated-ceos-bgp", "verify-isolated-ceos-rip", "verify-isolated-ceos-ripng",
                                               "verify-isolated-ceos-isis", "verify-isolated-ceos-eigrp", "verify-isolated-ceos-routed",
                                               "verify-isolated-ceos-switchport",
                                               "verify-isolated-ceos-subinterface",
                                               "verify-isolated-ceos-svi",
                                               "verify-isolated-ceos-management",
                                               "verify-runtime-unavailable", "report-matrix"))
        parser.add_argument("--platform", default="all", choices=("all", *features.platforms()))
        parser.add_argument("--feature", default="all", choices=("all", *features.by_key()))
        parser.add_argument("--family", default="", choices=("", features.INTERFACE, features.ROUTING, features.SERVICE_POLICY),
                            help="verify-matrix/report-matrix: restrict to one feature family.")
        parser.add_argument("--match", default="", help="verify-matrix/report-matrix: feature-key substring, e.g. NAT_ or FHRP_.")
        parser.add_argument("--remaining", action="store_true",
                            help="verify-matrix: assess only cells without a complete assessment (the default; explicit for scripts).")
        parser.add_argument("--reassess", action="store_true",
                            help="verify-matrix: also re-run cells whose assessment is already complete.")
        parser.add_argument("--isolated-live", action="store_true",
                            help="verify-matrix: run registered isolated-lab probes for cells that pass every prerequisite.")
        parser.add_argument("--summary", default="", help="Write the Markdown summary generated from the ledger to this path.")
        parser.add_argument("--test-type", choices=("static", "fixture"), default="static")
        parser.add_argument("--actor", default="nmas-capability-verifier")
        parser.add_argument("--runtime-version", default="")
        parser.add_argument("--evidence-ref", default="")
        parser.add_argument("--no-record", action="store_true")
        parser.add_argument("--live", action="store_true", help="Run the explicit reversible loopback verifier.")
        parser.add_argument("--allow-write", action="store_true", help="Required with --live; acknowledges a temporary device write.")
        parser.add_argument("--device", default="", help="Managed target; live verification is restricted by the verifier allowlist.")
        parser.add_argument("--report", default="", help="Write the machine-readable JSON ledger to this path.")
        parser.add_argument("--allow-incomplete", action="store_true", help="Explicit in-progress mode; never indicates Phase-4 completion.")

    def handle(self, *args, **options):
        if options["action"] == "verify-matrix":
            return self._handle_matrix(options)
        if options["action"] == "verify-isolated":
            return self._handle_isolated(options)
        if options["action"] == "verify-isolated-srl":
            return self._handle_isolated_srl(options)
        if options["action"] == "verify-isolated-vendor":
            return self._handle_isolated_vendor(options)
        if options["action"] == "verify-isolated-ceos-ospf":
            return self._handle_isolated_ceos_ospf(options)
        if options["action"] == "verify-isolated-ceos-ospf3":
            return self._handle_isolated_ceos_ospf3(options)
        if options["action"] == "verify-isolated-ceos-bgp":
            return self._handle_isolated_ceos_bgp(options)
        if options["action"] == "verify-isolated-ceos-rip":
            return self._handle_isolated_ceos_rip(options)
        if options["action"] == "verify-isolated-ceos-ripng":
            return self._handle_isolated_ceos_ripng(options)
        if options["action"] == "verify-isolated-ceos-isis":
            return self._handle_isolated_ceos_isis(options)
        if options["action"] == "verify-isolated-ceos-eigrp":
            return self._handle_isolated_ceos_eigrp(options)
        if options["action"] == "verify-isolated-ceos-routed":
            return self._handle_isolated_ceos_routed(options)
        if options["action"] == "verify-isolated-ceos-switchport":
            return self._handle_isolated_ceos_switchport(options)
        if options["action"] == "verify-isolated-ceos-subinterface":
            return self._handle_isolated_ceos_subinterface(options)
        if options["action"] == "verify-isolated-ceos-svi":
            return self._handle_isolated_ceos_svi(options)
        if options["action"] == "verify-isolated-ceos-management":
            return self._handle_isolated_ceos_management(options)
        if options["action"] == "verify-runtime-unavailable":
            return self._handle_runtime_unavailable(options)
        if options["action"] == "report-matrix":
            return self._handle_report(options)
        if options["platform"] == "all" or options["feature"] == "all":
            raise CommandError("Use verify-matrix for all-platform/all-feature enumeration.")
        if options["live"]:
            return self._handle_live(options)
        from core.services.capabilities import assessment
        from core.services.capabilities.offline_verify import verify_cell

        cell = verify_cell(options["platform"], features.by_key()[options["feature"]], head=_head())
        failures = [f"{name}: {r['reason']}" for name, r in cell.probes.items() if r["outcome"] in {"FAIL", "BLOCKED"}]
        ok = not failures
        detail = "; ".join(failures) if failures else "Actual offline fixture probes passed; live stages remain outstanding."
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write((self.style.SUCCESS if ok else self.style.ERROR)(detail))
        if not ok:
            raise CommandError("Capability verification failed closed.")

    def _write_reports(self, options, result):
        from core.services.capabilities import batch

        if options["report"]:
            path = Path(options["report"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        if options["summary"]:
            path = Path(options["summary"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(batch.summary_markdown(result))
        self.stdout.write(json.dumps({k: result[k] for k in ("total", "offline_attempted", "assessed", "unassessed", "supported", "unsupported")}))

    def _handle_matrix(self, options):
        """Batch-assess a platform / family / the whole matrix; one deliberate record per cell."""
        from core.services.capabilities import assessment, batch

        if options["live"] or options["device"]:
            raise CommandError("verify-matrix never targets production or an arbitrary device.")
        if options["remaining"] and options["reassess"]:
            raise CommandError("--remaining and --reassess are mutually exclusive.")
        if options["isolated_live"] != options["allow_write"]:
            raise CommandError("Isolated live probes need both --isolated-live and --allow-write; offline runs take neither.")
        head = _head()
        if not head:
            raise CommandError("Repository HEAD is required before any evidence can be recorded.")
        try:
            platforms, keys = batch.select(options["platform"], options["feature"], family=options["family"], match=options["match"])
        except ValueError as exc:
            raise CommandError(str(exc)) from None
        live_probes = None
        if options["isolated_live"]:
            from core.services.capabilities import batch_live

            live_probes = batch_live.registry()
        try:
            outcome = batch.assess_batch(
                platforms, keys, head=head, actor=options["actor"], reassess=options["reassess"],
                record=not options["no_record"], live_probes=live_probes,
                progress=lambda platform, counts: self.stdout.write(f"{platform}: {dict(sorted(counts.items()))}"))
        finally:
            if live_probes is not None:
                live_probes.close()   # restores every prepared isolated lab; raises if a baseline is not restored
        for (platform, key), error in sorted(outcome.errors.items()):
            self.stdout.write(self.style.ERROR(f"LIVE_ERROR {platform} {key}: {error}"))
        pending = sorted(k for k, action in outcome.actions.items() if action in {batch.PENDING_LIVE, batch.LIVE_ERROR})
        if pending:
            self.stdout.write("Cells that passed every prerequisite and still need an isolated live probe: " +
                              ", ".join(f"{p}/{k}" for p, k in pending))
        if options["no_record"]:
            fresh = {(c.platform, c.feature): c for c in outcome.cells}
            latest = assessment.latest_assessments()
            cells = [fresh.get((p, k)) or latest[p, k] for p in platforms for k in keys if (p, k) in fresh or (p, k) in latest]
            result = assessment.report(cells, selected_platforms=platforms, selected_features=keys)
            batch.check_report(result)
        else:
            result = batch.matrix_report(platforms, keys)
        result["batch_actions"] = outcome.counts()
        self._write_reports(options, result)
        if not options["allow_incomplete"]:
            try:
                assessment.require_complete(result)
            except ValueError as exc:
                raise CommandError(str(exc)) from None
        elif result["unassessed"]:
            self.stdout.write(self.style.WARNING("IN-PROGRESS ledger only; exhaustive Phase-4 acceptance has not passed."))

    def _handle_isolated(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import TARGETS, verify_loopback, verify_frr_static_route, verify_ceos_static_route
        from core.services.capabilities.offline_verify import verify_cell

        eligible = (options["platform"] in TARGETS and options["feature"] == "interface.LOOPBACK") or \
                   (options["platform"] == "ubuntu_frr" and options["feature"] in
                    {"routing.STATIC_IPV4", "routing.STATIC_IPV6"}) or \
                   (options["platform"] == "arista_ceos" and options["feature"] in
                    {"routing.STATIC_IPV4", "routing.STATIC_IPV6"})
        if not options["allow_write"] or not eligible:
            raise CommandError("Isolated live verification requires --allow-write and an implemented bounded target.")
        if options["device"] or options["live"]:
            raise CommandError("Isolated target identity is fixed by the harness; --device and --live are not accepted.")
        head = _head()
        cell = verify_cell(options["platform"], features.by_key()[options["feature"]], head=head)
        if options["feature"].startswith("routing.STATIC_") and options["platform"] == "arista_ceos":
            result = verify_ceos_static_route(options["feature"].rsplit("_", 1)[1])
        elif options["feature"].startswith("routing.STATIC_"):
            result = verify_frr_static_route(options["feature"].rsplit("_", 1)[1])
        else:
            result = verify_loopback(options["platform"])
        cell.runtime_version = TARGETS[options["platform"]][2]
        reference = f"live:nmas-cap-validation/{result.device}/{timezone.now().isoformat()}"
        for name in assessment.LIVE_PROBES:
            cell.probes[name] = assessment.probe("PASS", result.detail, test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(self.style.SUCCESS(f"{result.detail}; assessment_complete={cell.complete}; terminal={cell.status}"))

    def _handle_report(self, options):
        from core.services.capabilities import assessment, batch

        if options["live"] or options["allow_write"] or options["device"] or options["isolated_live"]:
            raise CommandError("report-matrix is read-only and does not contact devices.")
        try:
            platforms, keys = batch.select(options["platform"], options["feature"], family=options["family"], match=options["match"])
            result = batch.matrix_report(platforms, keys)
        except ValueError as exc:
            raise CommandError(str(exc)) from None
        self._write_reports(options, result)
        if not options["allow_incomplete"]:
            try:
                assessment.require_complete(result)
            except ValueError as exc:
                raise CommandError(str(exc)) from None

    def _handle_isolated_srl(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_srlinux_loopback
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "nokia_srlinux" or options["feature"] != "interface.LOOPBACK" \
                or options["device"] or options["live"]:
            raise CommandError("SR Linux isolated verification requires the fixed loopback target and --allow-write.")
        cell = verify_cell(options["platform"], features.by_key()[options["feature"]], head=_head())
        outcome = verify_srlinux_loopback()
        cell.runtime_version = "ghcr.io/nokia/srlinux:24.10 / 24.10.7-191"
        reference = f"live:nmas-cap-validation/srl/{timezone.now().isoformat()}"
        cell.probes["parser_import"] = assessment.probe("PASS", "Real SR Linux CLI JSON readback imported the rendered loopback and address.",
                                                          test_type="LIVE", reference=reference)
        cell.probes["live_read"] = assessment.probe("PASS", "Isolated CLI JSON readback succeeded; NMAS operator import still lacks an SR Linux capture adapter.",
                                                     test_type="LIVE", reference=reference)
        cell.probes["live_write"] = assessment.probe("FAIL", "Rendered commands applied via isolated sr_cli; registered NMAS executor_for still refuses SR Linux.",
                                                      reason="EXECUTOR_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["live_post_write_validation"] = assessment.probe("FAIL", "Device-side JSON post-read succeeded; NMAS has no SR Linux postcheck adapter.",
                                                                       reason="POSTCHECK_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe("FAIL", "Isolated CLI detach/delete restored state; NMAS executor has no SR Linux compensation path.",
                                                        reason="COMPENSATION_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["runtime_validation"] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}; executor absent")

    def _handle_runtime_unavailable(self, options):
        from core.services.capabilities.runtime_scan import verify_unavailable_iosxr

        if options["platform"] != "cisco_iosxr" or options["feature"] != "all" or options["allow_write"] \
                or options["live"] or options["device"]:
            raise CommandError("This read-only artifact absence probe is restricted to all IOS XR features.")
        try:
            cells = verify_unavailable_iosxr(head=_head(), actor=options["actor"], record=not options["no_record"])
        except RuntimeError as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(f"IOS XR: {len(cells)} real offline/fixture probes plus runtime-absence investigations complete; all unsupported.")

    def _handle_isolated_ceos_ospf(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_ospfv2
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "routing.OSPFV2" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS OSPF isolated verification requires the fixed peer topology and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["routing.OSPFV2"], head=_head())
        outcome = verify_ceos_ospfv2()
        cell.runtime_version = "ceos:4.36.2F / FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-frr-ospf/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe("PASS" if outcome.compensation_verified else "FAIL", outcome.detail,
                                                        reason="" if outcome.compensation_verified else "COMPENSATION_ABSENT",
                                                        test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_bgp(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_bgp
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] not in {"routing.BGP_IPV4", "routing.BGP_IPV6"} \
                or options["device"] or options["live"]:
            raise CommandError("cEOS BGP isolated verification requires the fixed peer topology and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()[options["feature"]], head=_head())
        outcome = verify_ceos_bgp(options["feature"].rsplit("_", 1)[1])
        cell.runtime_version = "ceos:4.36.2F / FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-frr-{options['feature'].lower()}/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe("PASS" if outcome.compensation_verified else "FAIL", outcome.detail,
                                                        reason="" if outcome.compensation_verified else "COMPENSATION_ABSENT",
                                                        test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_ospf3(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_ospfv3
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "routing.OSPFV3" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS OSPFv3 isolated verification requires the fixed peer topology and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["routing.OSPFV3"], head=_head())
        outcome = verify_ceos_ospfv3()
        cell.runtime_version = "ceos:4.36.2F / FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-frr-ospf3/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe("PASS" if outcome.compensation_verified else "FAIL", outcome.detail,
                                                        reason="" if outcome.compensation_verified else "COMPENSATION_ABSENT",
                                                        test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_rip(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_ripv2
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "routing.RIPV2" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS RIP isolated verification requires the fixed peer topology and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["routing.RIPV2"], head=_head())
        outcome = verify_ceos_ripv2()
        cell.runtime_version = "ceos:4.36.2F / FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-frr-ripv2/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe("PASS" if outcome.compensation_verified else "FAIL", outcome.detail,
                                                        reason="" if outcome.compensation_verified else "COMPENSATION_ABSENT",
                                                        test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_ripng(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_ripng_absence
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "routing.RIPNG" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS RIPng grammar investigation requires the fixed disposable target and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["routing.RIPNG"], head=_head())
        detail = verify_ceos_ripng_absence()
        cell.runtime_version = "ceos:4.36.2F"
        reference = f"live:nmas-cap-validation/ceos-ripng-grammar/{timezone.now().isoformat()}"
        cell.probes["live_read"] = assessment.probe("PASS", "Isolated cEOS running configuration and NMAS normalized live facts were read successfully.",
                                                     test_type="LIVE", reference=reference)
        for name in ("live_write", "live_post_write_validation", "compensation", "runtime_validation"):
            cell.probes[name] = assessment.probe("FAIL" if name in {"live_write", "runtime_validation"} else "BLOCKED",
                                                  detail + f"; {name} cannot be exercised without a supported RIPng process.",
                                                  reason="PLATFORM_DOES_NOT_SUPPORT", test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_isis(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_isis_native
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "routing.ISIS" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS IS-IS native investigation requires the fixed peer topology and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["routing.ISIS"], head=_head())
        detail = verify_ceos_isis_native()
        cell.runtime_version = "ceos:4.36.2F / FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-frr-isis/{timezone.now().isoformat()}"
        cell.probes["live_read"] = assessment.probe("FAIL", "NMAS normalized route read saw the IS-IS learned prefix, but no IS-IS process/neighbor fact group exists; native CLI verified UP adjacency.",
                                                     reason="LIVE_READ_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["live_write"] = assessment.probe("FAIL", "Native cEOS IS-IS write formed an adjacency; NMAS has no IS-IS candidate renderer or registered process executor.",
                                                      reason="RENDERER_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["live_post_write_validation"] = assessment.probe("FAIL", "Native route and adjacency postread succeeded; NMAS has no IS-IS process/neighbor postcheck.",
                                                                       reason="POSTCHECK_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe("FAIL", "Manual inverse restored the disposable peers; NMAS has no IS-IS compensation path.",
                                                        reason="COMPENSATION_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["runtime_validation"] = assessment.probe("PASS", detail, test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_eigrp(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_eigrp_absence
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] not in \
                {"routing.EIGRP_IPV4", "routing.EIGRP_IPV6"} or options["device"] or options["live"]:
            raise CommandError("cEOS EIGRP grammar investigation requires the fixed disposable target and --allow-write.")
        family = options["feature"].rsplit("_", 1)[1]
        cell = verify_cell("arista_ceos", features.by_key()[options["feature"]], head=_head())
        detail = verify_ceos_eigrp_absence(family)
        cell.runtime_version = "ceos:4.36.2F"
        reference = f"live:nmas-cap-validation/ceos-eigrp-{family.lower()}-grammar/{timezone.now().isoformat()}"
        cell.probes["live_read"] = assessment.probe("PASS", "Isolated cEOS running configuration and NMAS normalized live facts were read successfully.",
                                                     test_type="LIVE", reference=reference)
        for name in ("live_write", "live_post_write_validation", "compensation", "runtime_validation"):
            cell.probes[name] = assessment.probe("FAIL" if name in {"live_write", "runtime_validation"} else "BLOCKED",
                                                  detail + f"; {name} cannot be exercised without a supported EIGRP process.",
                                                  reason="PLATFORM_DOES_NOT_SUPPORT", test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_routed(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_routed_physical
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "interface.ROUTED_PHYSICAL" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS routed physical verification requires fixed Ethernet2 and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["interface.ROUTED_PHYSICAL"], head=_head())
        outcome = verify_ceos_routed_physical()
        cell.runtime_version = "ceos:4.36.2F / Ubuntu-FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-routed-ethernet2/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe("FAIL", "Manual default-interface restored Ethernet2, but NMAS cannot prove compensation for modifying an existing physical port.",
                                                        reason="COMPENSATION_ABSENT", test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_switchport(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_switchport
        from core.services.capabilities.offline_verify import verify_cell

        feature = options["feature"]
        if not options["allow_write"] or options["platform"] != "arista_ceos" or feature not in \
                {"interface.ACCESS", "interface.TRUNK"} or options["device"] or options["live"]:
            raise CommandError("cEOS switchport verification requires fixed Ethernet2 and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()[feature], head=_head())
        outcome = verify_ceos_switchport(feature.split(".", 1)[1])
        cell.runtime_version = "ceos:4.36.2F / Ubuntu-FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-{feature.lower().replace('.', '-')}-ethernet2/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe(
            "FAIL", "Manual default-interface restored Ethernet2, but NMAS cannot prove compensation for modifying an existing physical port.",
            reason="COMPENSATION_ABSENT", test_type="LIVE", reference=reference,
        )
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_subinterface(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_subinterface
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "interface.SUBINTERFACE" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS subinterface verification requires fixed Ethernet2.44 and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["interface.SUBINTERFACE"], head=_head())
        outcome = verify_ceos_subinterface()
        cell.runtime_version = "ceos:4.36.2F / Ubuntu-FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-subinterface-ethernet2-44/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe(
            "FAIL", "Tagged child compensation was exercised, but changing its pre-existing physical parent cannot be compensated by NMAS.",
            reason="COMPENSATION_ABSENT", test_type="LIVE", reference=reference,
        )
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_svi(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_svi
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "interface.SVI" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS SVI verification requires fixed VLAN44 and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["interface.SVI"], head=_head())
        outcome = verify_ceos_svi()
        cell.runtime_version = "ceos:4.36.2F / Ubuntu-FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-svi-vlan44/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe(
            "FAIL", "Manual inverse restored VLAN44, Vlan44 and the physical port; NMAS preflight cannot prove an inverse for the whole SVI candidate.",
            reason="COMPENSATION_ABSENT", test_type="LIVE", reference=reference,
        )
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_ceos_management(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_ceos_management
        from core.services.capabilities.offline_verify import verify_cell

        if not options["allow_write"] or options["platform"] != "arista_ceos" or options["feature"] != "interface.MANAGEMENT" \
                or options["device"] or options["live"]:
            raise CommandError("cEOS management verification requires fixed disposable Management0 and --allow-write.")
        cell = verify_cell("arista_ceos", features.by_key()["interface.MANAGEMENT"], head=_head())
        outcome = verify_ceos_management()
        cell.runtime_version = "ceos:4.36.2F / Ubuntu-FRR 8.4.4 peer"
        reference = f"live:nmas-cap-validation/ceos-management0-secondary/{timezone.now().isoformat()}"
        for name in ("parser_import", "live_read", "live_write", "live_post_write_validation", "runtime_validation"):
            cell.probes[name] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe(
            "PASS" if outcome.compensation_verified else "FAIL", outcome.detail,
            reason="" if outcome.compensation_verified else "COMPENSATION_ABSENT", test_type="LIVE", reference=reference,
        )
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}")

    def _handle_isolated_vendor(self, options):
        from django.utils import timezone
        from core.services.capabilities import assessment
        from core.services.capabilities.isolated_live import verify_iosxe_loopback, verify_sonic_loopback
        from core.services.capabilities.offline_verify import verify_cell

        runners = {
            "cisco_c8000v_iosxe": (verify_iosxe_loopback, "vrnetlab/cisco_c8000v:17.06.01a"),
            "sonic": (verify_sonic_loopback, "SONiC.master.1236848-ad5af6706"),
        }
        if not options["allow_write"] or options["platform"] not in runners or options["feature"] != "interface.LOOPBACK" \
                or options["device"] or options["live"]:
            raise CommandError("Vendor isolated verification requires the fixed loopback target and --allow-write.")
        cell = verify_cell(options["platform"], features.by_key()[options["feature"]], head=_head())
        runner, version = runners[options["platform"]]
        outcome = runner()
        cell.runtime_version = version
        reference = f"live:disposable/{outcome.device}/{timezone.now().isoformat()}"
        cell.probes["parser_import"] = assessment.probe("PASS", "Actual device configuration imported through the platform parser.",
                                                          test_type="LIVE", reference=reference)
        cell.probes["live_read"] = assessment.probe("PASS", "Isolated platform configuration and operational state read after write.",
                                                     test_type="LIVE", reference=reference)
        cell.probes["live_write"] = assessment.probe("FAIL", "Isolated native write succeeded; NMAS executor_for has no registered platform adapter.",
                                                      reason="EXECUTOR_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["live_post_write_validation"] = assessment.probe("FAIL", "Device-side readback succeeded; NMAS has no platform postcheck path.",
                                                                       reason="POSTCHECK_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["compensation"] = assessment.probe("FAIL", "Native inverse restored the disposable device; NMAS has no platform compensation adapter.",
                                                        reason="COMPENSATION_ABSENT", test_type="LIVE", reference=reference)
        cell.probes["runtime_validation"] = assessment.probe("PASS", outcome.detail, test_type="LIVE", reference=reference)
        if not options["no_record"]:
            assessment.persist(cell, actor=options["actor"])
        self.stdout.write(f"{outcome.detail}; assessment_complete={cell.complete}; terminal={cell.status}; NMAS executor absent")

    def _handle_live(self, options):
        if not options["allow_write"]:
            raise CommandError("--live requires explicit --allow-write; no device was contacted.")
        if options["feature"] != "interface.LOOPBACK":
            raise CommandError("The live harness currently supports only interface.LOOPBACK.")
        from core.services.capabilities.live_verify import verify_loopback
        from core.services.execution.executors.base import ExecutorError
        from core.services.health.live import LiveError

        try:
            result = verify_loopback(options["platform"], device_name=options["device"])
        except (ValueError, RuntimeError, ExecutorError, LiveError) as exc:
            if not options["no_record"]:
                for axis in (Axis.LIVE_WRITE, Axis.LIVE_POST_WRITE_VALIDATION, Axis.COMPENSATION, Axis.RUNTIME_VALIDATION):
                    evidence.record_evidence(
                        platform=options["platform"], feature=options["feature"], axis=axis,
                        status=EvidenceStatus.FAILED, source="nmas-capabilities-live", detail=str(exc),
                        recorded_by=options["actor"], evidence_type=EvidenceType.LIVE,
                        repository_head=_head(), runtime_version=options["runtime_version"],
                    )
            raise CommandError("Live capability verification failed closed after restoration was attempted.") from None
        if not options["no_record"]:
            for axis in (Axis.LIVE_READ, Axis.LIVE_WRITE, Axis.LIVE_POST_WRITE_VALIDATION, Axis.COMPENSATION,
                         Axis.RUNTIME_VALIDATION):
                evidence.record_evidence(
                    platform=result.platform, feature=options["feature"], axis=axis, status=EvidenceStatus.VERIFIED,
                    source="nmas-capabilities-live", detail=result.detail, evidence_ref=options["evidence_ref"],
                    recorded_by=options["actor"], evidence_type=EvidenceType.LIVE,
                    repository_head=_head(), runtime_version=options["runtime_version"],
                )
        self.stdout.write(self.style.SUCCESS(result.detail))
