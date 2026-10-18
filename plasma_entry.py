"""Entry point for the Plasma one-file executable.

PyInstaller bundles this module plus the `plasma` package, Pydantic and the
Python runtime into a single native binary. The frozen binary re-enters
itself through the hidden `_bridge` subcommand to execute a bundle's
bridge.py in-process, so no Python installation is required on the host.
"""
import sys

import pydantic  # noqa: F401 - ensure PyInstaller collects the runtime model layer

from plasma.cli import main

if __name__ == "__main__":
    sys.exit(main())
