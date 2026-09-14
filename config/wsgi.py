"""
WSGI entrypoint (standard Django 5.2 shape).

Settings module selection uses ``setdefault`` so DJANGO_SETTINGS_MODULE always
wins if provided (§54.1: the environment chooses dev/staging/prod/test).
"""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

application = get_wsgi_application()
