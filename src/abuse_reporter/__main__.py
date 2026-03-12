"""Entry point for ``python -m abuse_reporter`` and the ``abusereport`` CLI."""

import argparse

from abuse_reporter.runner import run_agent


def main() -> None:
    """Parse CLI arguments and run the abuse reporter agent."""
    parser = argparse.ArgumentParser(
        prog="abusereport",
        description="Fetch server logs, detect abusive traffic, and send reports.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=(
            "Process logs and show what would be sent, "
            "but skip emails, Discord messages, and DB writes."
        ),
    )
    args = parser.parse_args()
    run_agent(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
