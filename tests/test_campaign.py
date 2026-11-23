from phishguard.engine import campaign
from phishguard.storage.store import Store


def test_run_campaign_dry_run(cfg, targets_csv):
    store = Store(cfg.database.path)
    summary = campaign.run_campaign(
        cfg=cfg,
        store=store,
        campaign_name="demo",
        template_name="password_reset",
        targets_file=targets_csv,
        dry_run=True,
    )
    assert summary["dry_run"] is True
    assert summary["targets"] == 2
    assert summary["delivered"] == 2
    assert summary["failed"] == 0

    stats = store.campaign_stats(summary["campaign_id"])
    assert stats["delivered"] == 2


def test_run_campaign_unknown_template(cfg, targets_csv):
    store = Store(cfg.database.path)
    try:
        campaign.run_campaign(cfg, store, "demo", "does_not_exist", targets_csv)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown template")
