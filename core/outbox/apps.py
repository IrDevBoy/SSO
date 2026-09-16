"""
Outbox infrastructure app configuration (P0.4, decision A-2).

``core.outbox`` is a cross-cutting infrastructure subsystem of the monolith
(ARCHITECTURE.md §7.1 "infrastructure services of the monolith"; §55.7),
NOT a bounded-context domain app. It exists so the transactional outbox
table (§29.4) has an owner inside Django's migration framework while the
domain contexts remain unregistered (P0 skeleton rule).

P0 carries NO domain logic: no producers, no relay, no workers (§29 relay is
a separate process — later sub-phase). Only the table contract lives here.
"""

from django.apps import AppConfig


class OutboxConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core.outbox"
    label = "outbox"
    verbose_name = "UIAP Outbox (infrastructure)"
