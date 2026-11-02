"""Non-destructive acceptance self-test of the Phase-18 Raw Configlet sandbox verifier.

    python manage.py raw_verifier_selftest --platform ubuntu_frr
    RAW_VERIFIER_ALLOW_PRIVILEGED=1 python manage.py raw_verifier_selftest --platform arista_ceos

It runs ONE harmless synthetic VALID snippet and ONE harmless synthetic INVALID snippet through the real ``verify_raw_configlet``
(static gate -> capability -> isolated sandbox), then proves no ``clab-rawverify-*`` container remains.  It uses no database row, no
Change, no managed device, no credential and no network; the snippets are never applied anywhere.  Exit status 0 only when the
valid snippet is accepted (PASS), the invalid one is BLOCKED by the platform parser, and cleanup is proven.  If the sandbox
backend is unavailable (missing image, disabled, no runtime) the run reports INCOMPLETE and exits 2 -- it never fakes a result.
"""

from __future__ import annotations

from types import SimpleNamespace

from django.core.management.base import BaseCommand

from core.services.raw_configlets import sandbox, text as text_module, verifier

SAMPLES = {
    "ubuntu_frr": (
        "router ospf\n ospf router-id 192.0.2.1\n network 192.0.2.0/24 area 0\n",
        "router ospf\n ospf router-id NOT-AN-IP\n frobnicate the thing\n",
    ),
    "arista_ceos": (
        "interface Loopback99\n   description synthetic raw verifier selftest\n   ip address 192.0.2.99/32\n",
        "interface Loopback99\n   frobnicate nonsense\n   ip address 999.1.1.1/32\n",
    ),
}


def _revision(platform: str, content: str):
    normalized = text_module.normalize(content)
    return SimpleNamespace(content=normalized, content_hash=text_module.content_hash(normalized), platform=platform)


class Command(BaseCommand):
    help = "Verify a harmless valid and a harmless invalid synthetic snippet in the real isolated sandbox, then prove cleanup."

    def add_arguments(self, parser):
        parser.add_argument("--platform", choices=sorted(SAMPLES), required=True)

    def handle(self, *args, **options):
        platform = options["platform"]
        valid, invalid = (_revision(platform, sample) for sample in SAMPLES[platform])
        results = {}
        for label, revision in (("valid", valid), ("invalid", invalid)):
            outcome = verifier.verify_raw_configlet(revision)
            results[label] = outcome
            sandbox_info = outcome.evidence.get("sandbox", {})
            self.stdout.write(
                f"{platform} {label}: result={outcome.result} codes={sorted({f['code'] for f in outcome.findings})} "
                f"started={sandbox_info.get('started')} privileged={sandbox_info.get('privileged')} network={sandbox_info.get('network')} "
                f"cleanup={sandbox_info.get('cleanup')} backend={outcome.provenance.get('backend')}"
            )
        leftover = sandbox.run_process(
            [sandbox.DOCKER, "ps", "-a", "-q", "--filter", "name=^/clab-rawverify-"], timeout=30,
        )
        clean = leftover.error == "" and leftover.returncode == 0 and not leftover.output.strip()
        self.stdout.write(f"sandbox containers remaining after the run: {'0' if clean else 'UNKNOWN/NONZERO'}")
        if any(o.result == "INCOMPLETE" for o in results.values()):
            self.stdout.write("RESULT: INCOMPLETE (the sandbox backend could not complete; nothing was proven)")
            raise SystemExit(2)
        passed = results["valid"].result == "PASS" and results["invalid"].result == "BLOCKED" and clean
        self.stdout.write(f"RESULT: {'PASS' if passed else 'FAIL'}")
        raise SystemExit(0 if passed else 1)
