"""Temporary covering-route shield around a planned route replacement (cEOS, this lab's access design only).

``lab`` builds the proven transitions, ``gates`` holds the fail-closed prechecks, ``runner.execute`` is the service entry
point (refuses everything that is not READY in ``readiness``).  See docs/V2_LOSSLESS_ROUTE_SHIELD.md.
"""

from . import checks, core_cover, gates, lab, lifecycle, migration, model, readiness, runner  # noqa: F401
from .model import ShieldError, Transition  # noqa: F401
from .runner import Environment, Result, execute  # noqa: F401
