"""The five views, in sidebar order."""

from .automation import AutomationView
from .connectivity import ConnectivityView
from .counters import CountersView
from .nsot import NsotView
from .telemetry import TelemetryView

VIEWS = (ConnectivityView, TelemetryView, NsotView, AutomationView, CountersView)
