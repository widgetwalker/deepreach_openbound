"""Logging configuration for DeepReach."""

import logging
import sys


def get_logger(name: str = "deepreach") -> logging.Logger:
    """Get configured logger instance."""
    logger = logging.getLogger(name)

    if not logger.handlers:  # Avoid adding handlers multiple times
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger
