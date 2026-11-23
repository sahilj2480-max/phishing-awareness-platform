"""Email template definitions and rendering."""

from __future__ import annotations

from typing import Dict

# Placeholders available to every template:
#   {first_name}   - recipient first name (falls back to "there")
#   {name}         - recipient full name
#   {department}   - recipient department
#   {tracking_url} - click-tracking link back to the PhishGuard server
#   {pixel_url}    - open-tracking pixel URL
#   {brand_domain} - spoofed domain shown to the recipient

EMAIL_TEMPLATES: Dict[str, Dict[str, str]] = {
    "password_reset": {
        "subject": "Action required: verify your account password",
        "html": """
<html><body style="font-family: Arial, sans-serif; color: #333;">
<p>Dear {first_name},</p>
<p>We detected unusual sign-in activity on your account. For your security,
you must verify your password within <b>24 hours</b> or your account will be
suspended.</p>
<p><a href="{tracking_url}" style="background:#d93025;color:#fff;padding:10px 16px;
text-decoration:none;border-radius:4px;">Verify Account Now</a></p>
<p>If you did not request this, please ignore this message.</p>
<p>— {from_name}</p>
<img src="{pixel_url}" width="1" height="1" alt="" />
</body></html>
""",
    },
    "invoice": {
        "subject": "Overdue invoice #{invoice_no} — payment required",
        "html": """
<html><body style="font-family: Arial, sans-serif; color: #333;">
<p>Dear {name},</p>
<p>This is a reminder that invoice <b>#{invoice_no}</b> is now overdue. A late
fee will be applied if payment is not received within 48 hours.</p>
<p>Please review and download your invoice below.</p>
<p><a href="{tracking_url}" style="background:#1a73e8;color:#fff;padding:10px 16px;
text-decoration:none;border-radius:4px;">View Invoice</a></p>
<p>Thank you,<br/>Accounts Receivable</p>
<img src="{pixel_url}" width="1" height="1" alt="" />
</body></html>
""",
    },
    "hr_policy": {
        "subject": "IMPORTANT: Updated HR policy requires your acknowledgement",
        "html": """
<html><body style="font-family: Arial, sans-serif; color: #333;">
<p>Dear {first_name},</p>
<p>The Human Resources department has updated the employee handbook. All
employees in <b>{department}</b> must acknowledge the new policy document.</p>
<p>Please review and sign the updated policy by clicking the link below.</p>
<p><a href="{tracking_url}" style="background:#188038;color:#fff;padding:10px 16px;
text-decoration:none;border-radius:4px;">Review &amp; Acknowledge</a></p>
<p>— Human Resources</p>
<img src="{pixel_url}" width="1" height="1" alt="" />
</body></html>
""",
    },
}


def list_templates() -> list[str]:
    return sorted(EMAIL_TEMPLATES.keys())


def render(template_name: str, context: Dict[str, str]) -> Dict[str, str]:
    """Render a template into (subject, html_body) using the given context."""
    if template_name not in EMAIL_TEMPLATES:
        raise ValueError(f"unknown template: {template_name}")
    tpl = EMAIL_TEMPLATES[template_name]
    subject = tpl["subject"].format_map(_SafeDict(context))
    html = tpl["html"].format_map(_SafeDict(context))
    return {"subject": subject, "html": html}


class _SafeDict(dict):
    """Return a placeholder verbatim for missing keys instead of raising."""

    def __missing__(self, key):
        return "{" + key + "}"
