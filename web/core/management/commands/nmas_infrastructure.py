"""V2 Phase 8: drive and inspect the infrastructure projections (NetBox / topology / monitoring) from the lifecycle outbox.

    manage.py nmas_infrastructure dispatch [--consumer nsot|topology|monitoring] [--limit N]
    manage.py nmas_infrastructure status
    manage.py nmas_infrastructure export-targets [--path FILE]       (default monitoring/runtime/nmas-dynamic-targets.json)
    manage.py nmas_infrastructure push-grafana --url URL --org ORG --bucket BUCKET   (token from NMAS_INFLUX_TOKEN only)
    manage.py nmas_infrastructure collect [--targets FILE] [--url URL --org ORG --bucket BUCKET]
        read every exported target over its management path (core.services.infrastructure.collector); push when --url is given

NetBox writes stay disabled unless settings.NMAS_NSOT_RECONCILE_WRITE is True (the projection is then PLANNED).
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from core.services.infrastructure import collector, dispatcher, grafana, monitoring


class Command(BaseCommand):
    help = "Dispatch lifecycle facts to the NetBox / topology / monitoring consumers, or show their status."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        run = sub.add_parser("dispatch")
        run.add_argument("--consumer", choices=sorted(dispatcher.CONSUMERS), default=None)
        run.add_argument("--limit", type=int, default=50)
        sub.add_parser("status")
        export = sub.add_parser("export-targets")
        export.add_argument("--path", default=None)
        push = sub.add_parser("push-grafana")
        push.add_argument("--url", required=True)
        push.add_argument("--org", required=True)
        push.add_argument("--bucket", required=True)
        collect = sub.add_parser("collect")
        collect.add_argument("--targets", default=None)
        collect.add_argument("--url", default=None)
        collect.add_argument("--org", default=None)
        collect.add_argument("--bucket", default=None)

    def handle(self, *args, **options):
        action = options["action"]
        if action == "dispatch":
            result = dispatcher.dispatch(options["consumer"], limit=options["limit"])
            self.stdout.write(json.dumps({k: result[k] for k in ("consumer", "processed", "counts")}, sort_keys=True))
        elif action == "status":
            self.stdout.write(json.dumps(dispatcher.status(), sort_keys=True, indent=2))
        elif action == "export-targets":
            try:
                path = monitoring.write_runtime_targets(options["path"])
            except FileNotFoundError as exc:
                raise CommandError("RUNTIME_DIRECTORY_MISSING") from exc
            self.stdout.write(str(path))
        elif action == "push-grafana":
            try:
                result = grafana.push(grafana.lifecycle_points(), url=options["url"], org=options["org"], bucket=options["bucket"])
            except grafana.PushError as exc:
                raise CommandError(str(exc)) from None
            self.stdout.write(json.dumps(result, sort_keys=True))
        elif action == "collect":
            push = None
            if options["url"]:
                if not (options["org"] and options["bucket"]):
                    raise CommandError("INFLUX_ORG_AND_BUCKET_REQUIRED")
                push = {"url": options["url"], "org": options["org"], "bucket": options["bucket"]}
            try:
                report = collector.run(targets_path=options["targets"], push=push)
            except collector.TargetFileError as exc:
                raise CommandError(str(exc)) from None
            self.stdout.write(json.dumps(report, sort_keys=True))
