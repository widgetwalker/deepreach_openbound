"""Logging configuration for DeepReach."""

from __future__ import annotations

import logging
import sys


def get_logger(name: str = "deepreach") -> logging.Logger:
    """Return a configured logger, creating the handler once."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger
