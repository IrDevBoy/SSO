"""UIAP Identity bounded context (§9.1 context #1).

P0.6.1: storage + lifecycle foundation only (§11.2/§11.4, §12.0, §34.4).
No credential mechanics, no outbox emission (P0.6.2), no external IO.
"""

from django.apps import AppConfig


class IdentityConfig(AppConfig):
    name = "contexts.identity"
    label = "identity"
    verbose_name = "UIAP Identity (§9.1)"
