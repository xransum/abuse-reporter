"""Outbound SMTP email for abuse reports."""

import smtplib
from email.message import EmailMessage

from abuse_reporter.config import SmtpConfig


def send_abuse_report(
    cfg: SmtpConfig,
    to_address: str,
    subject: str,
    body: str,
    dry_run: bool = False,
) -> None:
    """Build and send an abuse report email.

    Args:
        cfg: SMTP connection configuration.
        to_address: The recipient email address.
        subject: The email subject line.
        body: The plain-text email body.
        dry_run: When True, print what would be sent without transmitting.
    """
    msg = create_email_message(cfg, to_address, subject, body)

    if dry_run:
        print(f"[DRY-RUN] Would send email to {to_address!r} with subject {subject!r}.")
        return

    send_email_via_smtp(cfg, msg)


def create_email_message(
    cfg: SmtpConfig,
    to_address: str,
    subject: str,
    body: str,
) -> EmailMessage:
    """Construct an EmailMessage object.

    Args:
        cfg: SMTP config supplying the From address.
        to_address: The recipient email address.
        subject: The email subject line.
        body: The plain-text email body.

    Returns:
        A fully populated EmailMessage ready to send.
    """
    msg = EmailMessage()
    msg["From"] = cfg.user
    msg["To"] = to_address
    msg["Cc"] = cfg.user
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def send_email_via_smtp(cfg: SmtpConfig, msg: EmailMessage) -> None:
    """Transmit an EmailMessage via SMTP with STARTTLS.

    Args:
        cfg: SMTP connection configuration.
        msg: The message to send.
    """
    with smtplib.SMTP(cfg.host, cfg.port) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(cfg.user, cfg.password)
        server.send_message(msg)
