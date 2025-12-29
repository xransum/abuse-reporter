"""Main file for the abuse_reporter package."""

from abuse_reporter.runner import run_agent


def main() -> None:
    """Main entry point for the abuse_reporter package."""
    run_agent()


if __name__ == "__main__":
    main()
