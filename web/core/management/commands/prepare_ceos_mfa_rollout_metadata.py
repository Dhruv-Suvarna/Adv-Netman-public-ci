"""Generic command name for the device-aware cEOS MFA metadata preparer."""

from .prepare_r1_mfa_rollout_metadata import Command as CompatibleCommand


class Command(CompatibleCommand):
    help = "Prepare non-secret metadata for one eligible managed cEOS MFA rollout; never touches a device."
