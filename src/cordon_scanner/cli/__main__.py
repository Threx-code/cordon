"""Allow `python -m cordon_scanner.cli.main`, which the container entrypoint uses."""

from cordon_scanner.cli.main import CommandLine

if __name__ == "__main__":
    raise SystemExit(CommandLine.main())
