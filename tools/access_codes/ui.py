#!/usr/bin/env python3
"""Convenience launcher for the graphical access code UI."""

import sys

import generate


def main() -> None:
    # Always force the --ui flag so running this file opens the GUI directly.
    argv = list(sys.argv)
    if "--ui" not in argv:
        argv.append("--ui")
        sys.argv = argv
    generate.main()


if __name__ == "__main__":
    main()
