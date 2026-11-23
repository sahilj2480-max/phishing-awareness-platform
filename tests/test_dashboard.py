from phishguard.landing.app import create_app
from phishguard.storage.store import Store


def test_dashboard_renders_with_data(tmp_path):
    store = Store(str(tmp_path / "dash.db"))
    cid = store.create_campaign("demo", "password_reset")
    tid = store.add_target("alice@example.com", "Alice", "Finance")
    did = store.add_delivery(cid, tid, "tok1")
    store.mark_delivered(did)
    store.record_event(did, "open")
    store.record_event(did, "click")

    client = create_app(store).test_client()
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "PhishGuard Dashboard" in html
    assert "demo" in html


def test_dashboard_empty_state(tmp_path):
    store = Store(str(tmp_path / "empty.db"))
    client = create_app(store).test_client()
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "No campaigns yet" in resp.get_data(as_text=True)
