"""Allow `python -m cordon.cli.main`, which the container entrypoint uses."""

from cordon.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
