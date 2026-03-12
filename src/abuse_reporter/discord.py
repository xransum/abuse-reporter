"""Discord webhook client for sending notification messages."""

import sys

import requests
from requests.exceptions import RequestException


class DiscordWebhook:
    """Thin wrapper around a Discord incoming webhook URL."""

    def __init__(self, webhook_url: str) -> None:
        """Initialise the client with a webhook URL.

        Args:
            webhook_url: The Discord webhook URL.  Pass an empty string to
                disable notifications silently.
        """
        self.webhook_url = webhook_url

    def send_message(self, content: str, dry_run: bool = False) -> None:
        """Post a message to the Discord webhook.

        Args:
            content: The message body to send.
            dry_run: When True, print what would be posted without sending.
        """
        if not self.webhook_url:
            return

        if dry_run:
            print(f"[DRY-RUN] Would post to Discord: {content!r}")
            return

        try:
            response = requests.post(
                self.webhook_url,
                json={"content": content},
                timeout=10,
            )
            response.raise_for_status()
        except RequestException as exc:
            print(f"Failed to send Discord message: {exc}", file=sys.stderr)
