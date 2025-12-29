"""Module for Discord webhook messaging."""

import sys

import requests
from requests.exceptions import RequestException


class DiscordWebhook:
    """A simple Discord webhook client for sending messages."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_message(self, content: str):
        """
        Sends a message to the Discord webhook.

        Args:
            content (str): The message content to send.
        """
        if not self.webhook_url:
            print(
                "Discord webhook URL not provided, skipping Discord notification."
            )
            return

        data = {"content": content}
        try:
            response = requests.post(self.webhook_url, json=data, timeout=10)
            response.raise_for_status()
        except RequestException as e:
            print(f"Failed to send Discord message: {e}", file=sys.stderr)
