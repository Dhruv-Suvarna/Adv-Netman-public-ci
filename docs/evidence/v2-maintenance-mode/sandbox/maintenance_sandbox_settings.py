"""Scratch Django settings for the Maintenance Mode sandbox runs: an isolated SQLite file named by NMAS_SANDBOX_DB.
Refuses to start without it, so a sandbox run can never open the deployed database."""
import os

from config.settings import *  # noqa: F401,F403

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.environ["NMAS_SANDBOX_DB"], "OPTIONS": {"timeout": 30}}}
