"""Maintenance Mode foundation: the request, traffic-aware readiness, the directional drain plan, the fail-closed
entry gate, the lifecycle and its deadline.  Pure logic: evidence in, verdicts out.  Nothing here contacts a device,
and nothing here can execute a drain; the drain mechanisms are named and their readiness is read, not run.

The deciding rule: active production traffic with no proven lossless way to move it blocks.  Missing redundancy alone
never does: a device whose relevant production traffic is verified quiesced may enter maintenance.
"""

from . import evidence, gates, lifecycle, model, plan, policy, protection, readiness, store, visibility  # noqa: F401
