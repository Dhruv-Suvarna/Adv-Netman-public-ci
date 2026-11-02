"""The one-time LEGACY BASELINE bootstrap: adopt the pre-automation network as the initial Golden after a short real observation.

See docs/LEGACY_BASELINE_BOOTSTRAP.md.  This package READS the network (read-only, allowlisted, sanitized) and records evidence; it never
configures anything.  The scheduler entry point is the ``legacy_bootstrap`` management command.  The ONLY route to the initial Golden bundle is
``decision.approve``, reached from an explicit operator POST (or the operator-run command that calls the same function); a technical PASS
alone never creates one.  Normal probation and Golden promotion are untouched: seven days, unchanged.
"""
