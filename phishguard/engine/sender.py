"""SMTP delivery with a mandatory dry-run safety mode."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from typing import Optional

from ..config import SMTPConfig

logger = logging.getLogger("phishguard.sender")


def send_email(
    smtp: SMTPConfig,
    to_email: str,
    subject: str,
    html: str,
    dry_run: bool = True,
) -> bool:
    """Send an HTML email. Returns True on success.

    When ``dry_run`` is True (the default), nothing is sent over the network;
    the message is logged instead. This is a deliberate safety default so a
    simulation can never accidentally email a real person without intent.
    """
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((smtp.from_name, smtp.from_email))
    msg["To"] = to_email
    msg.set_content("This email requires an HTML-capable client.")
    msg.add_alternative(html, subtype="html")

    if dry_run:
        logger.info(
            "[DRY-RUN] would send email to=%s subject=%r from=%s",
            to_email,
            subject,
            smtp.from_email,
        )
        return True

    if not smtp.host or smtp.host == "smtp.example.com":
        logger.error("SMTP host is not configured (set smtp.host in config.yaml)")
        return False

    try:
        if smtp.use_tls:
            server = smtplib.SMTP(smtp.host, smtp.port, timeout=smtp.timeout)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=smtp.timeout)

        if smtp.username:
            server.login(smtp.username, smtp.password)
        server.send_message(msg)
        server.quit()
        logger.info("sent email to %s", to_email)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        logger.error("failed to send email to %s: %s", to_email, exc)
        return False
