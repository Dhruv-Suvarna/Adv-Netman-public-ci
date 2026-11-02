"""NMAS standalone challenge / operations console (Version 2 Phase 6).

A read-only Tkinter observation surface.  It is deliberately NOT part of the NMAS Django website: nothing here imports Django,
talks to the website over HTTP for data, or needs ``nmas-web.service`` to be running.  See
``docs/V2_PHASE6_STANDALONE_CHALLENGE_CONSOLE.md``.
"""

APP_NAME = "nmas-challenge-console"
APP_TITLE = "NMAS Challenge Console"
VERSION = "6.0.0"
