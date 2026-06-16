"""Lockfile parsers for DeepReach."""

from .npm import NpmLockfileParser
from .pip import PipLockfileParser

__all__ = ["NpmLockfileParser", "PipLockfileParser"]
