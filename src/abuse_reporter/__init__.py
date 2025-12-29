"""Init file for the abuse_reporter package."""

import os
from os import environ  # noqa: F401

from colorama import Fore, Style  # noqa: F401
from colorama import init as colorama_init
from dotenv import load_dotenv


colorama_init(autoreset=False)


# Determine the application root directory
app_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

# Load environment variables from the .env file located at the
# application root
load_dotenv(os.path.join(app_root, ".env"))

__all__ = [
    "app_root",
    "environ",
    "Fore",
    "Style",
]
