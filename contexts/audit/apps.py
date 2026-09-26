"""Audit bounded context app configuration (P0.7.2, §28; ADR-0006).

``contexts.audit`` is a bounded context (§9: audit is a first-class domain,
§28.1: "audit is a first-class domain"). It registers exactly when its
storage foundation lands (base.py INSTALLED_APPS convention from P0.6.1).
"""

from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "contexts.audit"
    label = "audit"
    verbose_name = "UIAP Audit (§28 tamper-evident audit platform)"
