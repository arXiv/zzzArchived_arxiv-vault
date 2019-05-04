"""Utility functions."""

import logging
import sys
import os

DEFAULT_FORMAT = ("application %(asctime)s - %(name)s - %(levelname)s:"
                  " \"%(message)s\"")
DATE_FORMAT = '%d/%b/%Y:%H:%M:%S %z'    # Used to format asctime.


def getLogger(name: str, fmt: str = DEFAULT_FORMAT,
              date_fmt: str = DATE_FORMAT) -> logging.Logger:
    """Get a new logger with a uniform configuration."""
    logger = logging.getLogger(name)
    logger.propagate = True
    logger.setLevel(int(os.environ.get('LOGLEVEL', 40)))
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=date_fmt))
    logger.handlers = []
    logger.addHandler(handler)
    return logger
