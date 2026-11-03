"""Dedicated management-process settings. Never serve HTTP with this module.

Opt-in alone does not authorize execution: command and versioned profile gates
must also pass. No migrations or native requests occur on import.
"""

import os

from .settings import *  # noqa: F403

DEBUG = False
ROOT_URLCONF = "auth.worker_urls"
USER_ADMIN_API_ENABLED = False
USER_ADMIN_WORKER_ENABLED = os.environ.get("USER_ADMIN_WORKER_ENABLED") == "1"
USER_ADMIN_NATIVE_EXECUTION_ENABLED = USER_ADMIN_WORKER_ENABLED
