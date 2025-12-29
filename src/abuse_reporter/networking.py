"""Module for retrieving WHOIS and IP information."""

import socket
import sys

import requests
import whois
from requests.exceptions import RequestException
from whois.exceptions import PywhoisError


def get_whois_info(
    ip_addr: str, retry: int = 0, max_retries: int = 3
) -> whois.WhoisEntry | None:
    """Retrieves WHOIS information for a given IP address.

    Args:
        ip_addr (str): The IP address to query.
        retry (int): The current retry attempt.
        max_retries (int): The maximum number of retry attempts.

    Returns:
        whois.WhoisEntry | None: The WHOIS information or None if the query fails.
    """
    try:
        w = whois.whois(ip_addr)
        return w

    except PywhoisError as e:
        if retry < max_retries:
            return get_whois_info(ip_addr, retry + 1, max_retries)

        print(f"Failed to get WHOIS info for {ip_addr}: {e}", file=sys.stderr)

        return None


def get_ip_info(ip_addr: str) -> dict | None:
    """Fetches information about a given IP address using the ipinfo.io API.

    Args:
        ip_addr (str): The IP address to retrieve information for.

    Returns:
        dict | None: A dictionary containing the IP address information if the
            request is successful, or None if an error occurs during the request.

    Notes:
        - This function uses the ipinfo.io API to fetch IP address details.
        - A timeout of 10 seconds is set for the API request.
        - If the request fails, an error message is printed to stderr, and None
            is returned.
    """
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip_addr}/json",
            timeout=10,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    " (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
                )
            },
        )
        response.raise_for_status()
        return response.json()

    except RequestException as e:
        print(f"Failed to get IP info for {ip_addr}: {e}", file=sys.stderr)
        return None


def get_hostname_from_ip(ip_addr: str) -> str:
    """Performs a reverse DNS lookup to get the hostname for a given IP address.

    Args:
        ip_addr (str): The IP address to look up.

    Returns:
        str: The hostname associated with the IP address, or "Unknown" if not
            found.
    """
    try:
        hostname, *_ = socket.gethostbyaddr(ip_addr)
        return hostname
    except socket.herror:
        return "Unknown"
