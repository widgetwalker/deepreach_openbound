#!/usr/bin/env python3
"""DeepReach CLI entry point."""
import sys
from . import __version__

def main():
    print(f"deepreach {__version__}")
    return 0

if __name__ == "__main__":
    sys.exit(main())