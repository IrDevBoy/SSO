"""
Development settings — P0.3 level.

Reads the ``DJANGO_DEBUG`` / ``DJANGO_ALLOWED_HOSTS`` contract declared in
``.env.example`` (§54.1: env-var configuration) so the template matches real
readers. DEBUG defaults to True for local laptops; a malformed DJANGO_DEBUG
value is a loud configuration error, never silently coerced (decision G-1).

Only dev honors DJANGO_DEBUG — staging/prod hard-code DEBUG=False and no
environment variable can flip them.
"""

from config.settings._env import env_bool, env_host_list
from config.settings.base import *  # noqa: F401,F403

# G-1 contract: local development truth, controllable via DJANGO_DEBUG.
DEBUG = env_bool("DJANGO_DEBUG", default=True)

# Unset keeps the historical localhost fallback; set-but-empty means no hosts
# (fail-closed, explicit, tested).
ALLOWED_HOSTS = env_host_list(
    "DJANGO_ALLOWED_HOSTS",
    default=["localhost", "127.0.0.1", "testserver"],
)
