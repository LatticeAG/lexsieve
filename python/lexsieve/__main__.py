"""`python -m lexsieve` — same command surface as bin/lexsieve.js."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
