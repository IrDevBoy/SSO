"""Relay process entrypoint (P0.7; §8.2, §54.2, ADR-0005).

The relay is a **separate process** from the application (§8.2: survives
deploys, own backpressure/alerts; §54.2: single leader via lease, N
replicas — the lease mechanism is a deployment-level concern; this module
is the process foundation and does not implement the lease).

Usage:

    DJANGO_SETTINGS_MODULE=config.settings.prod \
    UIAP_RELAY_SOURCE=<verified deployment issuer> \
    python -m relay

Configuration (all settings-backed, PD-8; §41.4 fail-closed posture):
- ``UIAP_RELAY_SOURCE``  : the CloudEvents ``source``. **Required** — the
  relay refuses to start without it (OQ-01: no invented issuer; refuse-to-
  publish would make the loop a no-op, so fail-closed at boot is the honest
  posture until OQ-01 resolves).
- ``UIAP_RELAY_URL``     : Redis-protocol URL (Valkey).
- stream/group/consumer/tuning: see :mod:`core.outbox.conf`.
"""

from __future__ import annotations

import logging
import os
import sys

import django


def main() -> int:
    django.setup()

    from core.outbox.conf import RelayConfigError, RelaySettings
    from core.outbox.relay import Relay
    from core.outbox.transport import StreamsTransport
    from core.outbox.transport import TransportError  # noqa: F401 (documented)

    import redis

    source = os.environ.get("UIAP_RELAY_SOURCE", "").strip()
    if not source:
        # OQ-01 OPEN: never invent a source; refuse to boot (fail-closed).
        logging.getLogger("uiap.relay").error(
            "relay boot refused: UIAP_RELAY_SOURCE is missing/empty — the "
            "relay never invents a CloudEvents source (OQ-01 OPEN, ADR-0005)."
        )
        return 2

    redis_url = os.environ.get("UIAP_RELAY_URL", "").strip()
    if not redis_url:
        logging.getLogger("uiap.relay").error(
            "relay boot refused: UIAP_RELAY_URL is missing/empty (§41.4 "
            "fail-closed configuration posture)."
        )
        return 2

    try:
        settings = RelaySettings(strict=True)
    except RelayConfigError as exc:
        logging.getLogger("uiap.relay").error("relay boot refused: %s", exc)
        return 2

    client = redis.Redis.from_url(redis_url)
    transport = StreamsTransport(
        client,
        stream=settings.stream,
        group=settings.group,
        consumer=settings.consumer,
        dlq_stream=settings.dlq_stream,
    )
    relay = Relay(transport, settings=settings, source=source)
    try:
        relay.run_forever()
    except KeyboardInterrupt:  # graceful SIGINT for container stop
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
