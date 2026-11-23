from phishguard.storage.store import Store


def test_add_and_get_target(tmp_path):
    store = Store(str(tmp_path / "store.db"))
    tid = store.add_target("alice@example.com", "Alice Smith", "Finance")
    targets = store.get_targets()
    assert len(targets) == 1
    assert targets[0]["email"] == "alice@example.com"
    assert targets[0]["department"] == "Finance"


def test_target_upsert(tmp_path):
    store = Store(str(tmp_path / "store.db"))
    store.add_target("alice@example.com", "Alice Smith", "Finance")
    store.add_target("alice@example.com", "Alice S.", "Audit")
    targets = store.get_targets()
    assert len(targets) == 1
    assert targets[0]["name"] == "Alice S."
    assert targets[0]["department"] == "Audit"


def test_campaign_lifecycle_and_events(tmp_path):
    store = Store(str(tmp_path / "store.db"))
    cid = store.create_campaign("demo", "password_reset")
    tid = store.add_target("bob@example.com", "Bob", "Eng")
    did = store.add_delivery(cid, tid, "token123")

    store.mark_delivered(did)
    store.record_event(did, "open")
    store.record_event(did, "click")
    store.record_event(did, "submit")

    stats = store.campaign_stats(cid)
    assert stats["delivered"] == 1
    assert stats["opened"] == 1
    assert stats["clicked"] == 1
    assert stats["submitted"] == 1
    assert stats["reported"] == 0


def test_unknown_event_type_rejected(tmp_path):
    store = Store(str(tmp_path / "store.db"))
    cid = store.create_campaign("demo", "password_reset")
    tid = store.add_target("bob@example.com", "Bob", "Eng")
    did = store.add_delivery(cid, tid, "token123")
    try:
        store.record_event(did, "bogus")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown event type")


def test_get_delivery_by_token(tmp_path):
    store = Store(str(tmp_path / "store.db"))
    cid = store.create_campaign("demo", "invoice")
    tid = store.add_target("carol@example.com", "Carol", "HR")
    store.add_delivery(cid, tid, "abc123")
    delivery = store.get_delivery_by_token("abc123")
    assert delivery is not None
    assert store.get_delivery_by_token("nope") is None
