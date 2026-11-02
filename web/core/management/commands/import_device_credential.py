"""Import one device password from an environment variable into the runtime provider."""
from __future__ import annotations

import os

from django.core.management.base import BaseCommand, CommandError

from modules.device_credentials import FileSecretProvider, SecretProviderError


class Command(BaseCommand):
    help = "Import a device credential from a named environment variable; values are never accepted on argv."

    def add_arguments(self, parser):
        parser.add_argument("--ref", required=True, help="runtime://device-credentials/<key> reference")
        parser.add_argument("--env-var", required=True, help="Name of the environment variable holding the value")
        parser.add_argument("--replace", action="store_true", help="Replace an existing reference (safe metadata only is printed)")

    def handle(self, *args, **options):
        name = options["env_var"]
        if not name.isidentifier() or name.upper() != name:
            raise CommandError("--env-var must be an uppercase environment-variable name.")
        value = os.environ.get(name)
        if not value:
            raise CommandError("The requested environment variable is missing or empty.")
        try:
            version = FileSecretProvider().initialize(options["ref"], value, replace=options["replace"])
        except SecretProviderError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(f"Imported {options['ref']} as non-secret version {version}."))
