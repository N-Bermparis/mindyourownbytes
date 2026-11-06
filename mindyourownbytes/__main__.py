"""Entry point for ``python -m mindyourownbytes``, and for the Windows download."""

import sys
from pathlib import Path

if sys.version_info < (3, 12):  # noqa: UP036
    # Running from a source checkout skips pip's requires-python check. Under
    # Python 3.11 the interface would crash during normal use: see pyproject.toml.
    sys.exit(f"mindyourownbytes needs Python 3.12 or newer, but this is {sys.version.split()[0]}.")

from mindyourownbytes.gui.main_window import main  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--self-test":
        from mindyourownbytes.selftest import run

        sys.exit(run(Path(sys.argv[2])))
    main()
