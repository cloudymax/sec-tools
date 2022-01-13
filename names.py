#!/usr/bin/env python3
"""
Functions for generating names, ids and such
"""

import subprocess
import logging as log
from logging import debug
import uuid

log_level = log.ERROR
program_log = log.getLogger("my-logger")
#program_log.basicConfig(stream=sys.stderr, level=log_level)
program_log.info("logging config loaded")


def random_uuid():
"""
returns a random uuid
"""

    try:
        return uuid.uuid4()
    
    except Exception:

        program_log.ERROR("failed to create random UUID")

