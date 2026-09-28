"""Allow ``python -m app`` as an entry point (equivalent to ``python run.py``)."""

from app.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
