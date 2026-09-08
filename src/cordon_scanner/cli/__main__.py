"""Allow `python -m cordon_scanner.cli.main`, which the container entrypoint uses."""

from cordon_scanner.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
