"""Allow ``python -m anchor ...`` with the repo root on sys.path."""

from .tool import main

if __name__ == "__main__":
    raise SystemExit(main())
