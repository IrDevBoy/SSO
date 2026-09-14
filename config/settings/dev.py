"""
Development settings — P0.2 skeleton level.

Inherits base and relaxes exactly what local development needs. No database,
cache, Celery, logging, or security-middleware configuration exists at this
level (each arrives with its own sub-phase per the §60 plan).
"""

from config.settings.base import *  # noqa: F401,F403

# Local development truth: visible errors on the laptop.
DEBUG = True

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]
