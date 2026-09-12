import sys

from .cli import main

if __name__ == "__main__":          # guard so `spawn` workers can re-import this
    sys.exit(main())
