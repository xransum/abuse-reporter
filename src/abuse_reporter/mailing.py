"""Module for sending abuse report emails via SMTP."""

import smtplib
from email.message import EmailMessage

from abuse_reporter.constants import (
    NO_SEND,
    SMTP_HOST,
    SMTP_PASS,
    SMTP_PORT,
    SMTP_USER,
)


def send_abuse_report(to_address: str, subject: str, body: str):
    """Sends an abuse report email to the specified recipient.

    Args:
        to_address (str): The recipient's email address.
        subject (str): The subject of the email.
        body (str): The content of the email.
    """
    msg = create_email_message(to_address, subject, body)
    if NO_SEND:
        print(
            f"[!] NO_SEND is enabled. Email to {to_address!r} with subject "
            f"{subject!r} not sent."
        )
        return

    send_email_via_smtp(msg)


def create_email_message(
    to_address: str, subject: str, body: str
) -> EmailMessage:
    """Creates an email message object.

    Args:
        to_address (str): The recipient's email address.
        subject (str): The subject of the email.
        body (str): The content of the email.

    Returns:
        EmailMessage: The constructed email message object.
    """
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = to_address
    msg["Cc"] = SMTP_USER
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def send_email_via_smtp(msg: EmailMessage):
    """Sends an email message using the SMTP server.

    Args:
        msg (EmailMessage): The email message to send.
    """
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
