#!/usr/bin/env python
"""UIAP management entrypoint (P0.2 Django skeleton).

The settings module uses ``setdefault`` so the environment always wins
(ARCHITECTURE.md v1.0.1 §54.1: environment selection via DJANGO_SETTINGS_MODULE,
see .env.example). Default = dev for local laptop use only.
"""
import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and available on "
            "your PYTHONPATH environment variable? Did you forget to activate a "
            "virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
