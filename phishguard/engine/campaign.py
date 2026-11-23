"""Campaign orchestration: token assignment, rendering, delivery, and metrics."""

from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, List

from ..config import Config
from ..storage.store import Store
from . import sender, templates, targets

logger = logging.getLogger("phishguard.campaign")


def _build_urls(cfg: Config, token: str) -> Dict[str, str]:
    base = cfg.server.base_url.rstrip("/")
    return {
        "tracking_url": f"{base}/c/{token}",
        "pixel_url": f"{base}/t/{token}",
    }


def _extra_context(template_name: str) -> Dict[str, str]:
    if template_name == "invoice":
        return {"invoice_no": str(secrets.randbelow(90000) + 10000)}
    return {}


def run_campaign(
    cfg: Config,
    store: Store,
    campaign_name: str,
    template_name: str,
    targets_file: str,
    dry_run: bool | None = None,
) -> Dict[str, Any]:
    """Run a full campaign: load targets, mint tokens, send, and return a summary."""
    if template_name not in templates.EMAIL_TEMPLATES:
        raise ValueError(f"unknown template: {template_name}")

    if dry_run is None:
        dry_run = cfg.dry_run

    recipient_list = targets.load_targets(targets_file)
    if not recipient_list:
        raise ValueError(f"no targets found in {targets_file}")

    campaign_id = store.create_campaign(campaign_name, template_name)
    delivered = 0
    failed = 0

    for target in recipient_list:
        target_id = store.add_target(target["email"], target["name"], target["department"])
        token = secrets.token_urlsafe(24)

        urls = _build_urls(cfg, token)
        ctx = targets.build_context(
            target,
            **urls,
            from_name=cfg.smtp.from_name,
            **_extra_context(template_name),
        )
        rendered = templates.render(template_name, ctx)

        delivery_id = store.add_delivery(campaign_id, target_id, token)
        ok = sender.send_email(
            cfg.smtp,
            target["email"],
            rendered["subject"],
            rendered["html"],
            dry_run=dry_run,
        )
        if ok:
            store.mark_delivered(delivery_id)
            delivered += 1
        else:
            failed += 1

    logger.info("campaign %r complete: %d delivered, %d failed", campaign_name, delivered, failed)
    return {
        "campaign_id": campaign_id,
        "campaign_name": campaign_name,
        "template": template_name,
        "targets": len(recipient_list),
        "delivered": delivered,
        "failed": failed,
        "dry_run": dry_run,
    }
