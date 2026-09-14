"""
Staging settings — P0.3 level.

Production-shaped posture, unchanged by the P0.3 refactor (same guarantees,
one shared helper): DEBUG hard-off, ALLOWED_HOSTS fail-closed from the
environment, SECRET_KEY fail-fast on missing AND empty (§41.4).
"""

from config.settings._env import env_host_list, required_secret
from config.settings.base import *  # noqa: F401,F403

DEBUG = False  # hard-off; no environment variable can change this

# Fail-closed: unset or set-but-empty UIAP_ALLOWED_HOSTS -> no hosts allowed.
ALLOWED_HOSTS = env_host_list("UIAP_ALLOWED_HOSTS", default=[])

SECRET_KEY = required_secret("UIAP_SECRET_KEY")
