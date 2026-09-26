"""P0.7 relay configuration contract (ADR-0005; owner-approved PD-8, PD-7).

Every operational name and tuning parameter is **settings/env-backed**
(PD-8: no invented literals in code). Defaults exist only so local dev and
the integration harness boot without a full deployment config; production
values come from the environment per §54.1. Nothing here invents a
``producer`` version or a CloudEvents ``source`` (OQ-01 is OPEN — BD-9,
ADR-0004).

Contract:

- ``UIAP_RELAY_STREAM``      main stream name (settings-backed, PD-8)
- ``UIAP_RELAY_GROUP``       consumer group (settings-backed, PD-8)
- ``UIAP_RELAY_CONSUMER``    consumer name (settings-backed, PD-8)
- ``UIAP_RELAY_CLAIM_BATCH`` claim batch size (implementation tuning)
- ``UIAP_RELAY_IDLE_MS``     XAUTOCLAIM min-idle-time in ms (PD-7: explicit,
                             tunable, NOT an architectural invariant)

The DLQ stream name is NOT configured: §29.4 pins the ``dlq.<group>``
naming contract, so the DLQ is derived from the configured group — the
template ``dlq.<group>`` is the one source-backed naming rule (§29.4,
`docs/ARCHITECTURE.md:2319`).
"""

from __future__ import annotations

import os

__all__ = [
    "RelayConfigError",
    "RelaySettings",
    "dlq_stream_name",
    "relay_settings_from_env",
]


class RelayConfigError(Exception):
    """Raised when relay configuration is missing/empty/invalid (fail-closed)."""


def relay_settings_from_env(
    env: dict[str, str] | None = None,
    *,
    strict: bool = False,
) -> dict[str, str]:
    """Read the relay contract from the environment.

    - ``strict=True`` (the production posture, §41.4): a missing/empty value
      raises :class:`RelayConfigError` — fail-closed, no silent fallback.
    - ``strict=False`` (dev/test/integration): the documented local defaults
      below keep the relay bootable without a deployment config.
    """
    env = dict(os.environ if env is None else env)

    def _get(name: str, default: str | None) -> str:
        value = env.get(name, "").strip()
        if value:
            return value
        if strict:
            raise RelayConfigError(
                f"{name} is required for the relay in this environment and "
                "was missing or empty (§41.4: fail-closed configuration)."
            )
        if default is None:
            raise RelayConfigError(f"{name} is required and has no default.")
        return default

    settings = {
        "stream": _get("UIAP_RELAY_STREAM", "uiap_events"),
        "group": _get("UIAP_RELAY_GROUP", "uiap_events_group"),
        "consumer": _get("UIAP_RELAY_CONSUMER", "uiap_relay_consumer"),
        "claim_batch": _get("UIAP_RELAY_CLAIM_BATCH", "50"),
        "idle_ms": _get("UIAP_RELAY_IDLE_MS", "60000"),
    }
    if not settings["claim_batch"].isdigit() or int(settings["claim_batch"]) <= 0:
        raise RelayConfigError("UIAP_RELAY_CLAIM_BATCH must be a positive integer.")
    if not settings["idle_ms"].isdigit() or int(settings["idle_ms"]) <= 0:
        raise RelayConfigError("UIAP_RELAY_IDLE_MS must be a positive integer (ms).")
    return settings


def dlq_stream_name(group: str) -> str:
    """§29.4 DLQ naming contract: ``dlq.<group>`` (the only LOCKED name)."""
    if not group or group.strip() != group:
        raise RelayConfigError("consumer group name must be non-empty and untrimmed.")
    return f"dlq.{group}"


class RelaySettings:
    """Typed view over :func:`relay_settings_from_env` (PD-8/PD-7 config seam)."""

    __slots__ = ("stream", "group", "consumer", "claim_batch", "idle_ms")

    def __init__(self, env: dict[str, str] | None = None, *, strict: bool = False):
        data = relay_settings_from_env(env, strict=strict)
        self.stream: str = data["stream"]
        self.group: str = data["group"]
        self.consumer: str = data["consumer"]
        self.claim_batch: int = int(data["claim_batch"])
        self.idle_ms: int = int(data["idle_ms"])

    @property
    def dlq_stream(self) -> str:
        return dlq_stream_name(self.group)
