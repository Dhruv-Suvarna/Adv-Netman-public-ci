"""Print the traffic runner's configuration document for the tracked inventory (JSON on stdout).

Read-only: contacts nothing and writes nothing.  The installer (``deploy/scripts/install_traffic_runner.sh``) runs it and installs the
output as the root-owned ``/etc/nmas/traffic-runner.json``; the runner then resolves endpoint ids from THAT file, never from a request.
"""

import json
import re

from django.core.management.base import BaseCommand, CommandError

from core.services.traffic import endpoints
from core.services.traffic.runner import config as runner_config


class Command(BaseCommand):
    help = "Render the traffic runner configuration (endpoint catalogue, pinned tools image id, allowed peer uid)."

    def add_arguments(self, parser):
        parser.add_argument("--tools-image", required=True, help="Image ID of the tools image (sha256:<64 hex>), never a tag.")
        parser.add_argument("--peer-uid", required=True, type=int, action="append", help="uid of the website service account (repeatable).")
        parser.add_argument("--instance", default="nmas")

    def handle(self, *args, **options):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", options["tools_image"]):
            raise CommandError("--tools-image must be an image ID (sha256:<64 hex>)")
        document = endpoints.runner_config(tools_image=options["tools_image"], allowed_peer_uids=options["peer_uid"], instance=options["instance"])
        try:
            runner_config.parse(document)          # the runner's own parser must accept what the installer is about to install
        except runner_config.ConfigError as exc:
            raise CommandError(f"the inventory does not render a valid runner configuration: {exc}") from exc
        self.stdout.write(json.dumps(document, indent=1, sort_keys=True))
