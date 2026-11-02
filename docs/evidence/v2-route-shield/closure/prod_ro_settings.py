"""READ-ONLY production settings for the dry run of code that is not deployed yet (PR #51).

The code is the PR worktree's.  The runtime is the deployed one: its credential store, its inventory and its database,
the database opened read-only (SQLite ``mode=ro``), so the dry run cannot record anything even by mistake.
"""
from pathlib import Path

from config.settings import *  # noqa: F401,F403

DEPLOY = Path("/home/student/Scripts/clab_dualstack_lab-deploy")
REPO_ROOT = DEPLOY
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": f"file:{DEPLOY}/web/db.sqlite3?mode=ro", "OPTIONS": {"uri": True}}}
