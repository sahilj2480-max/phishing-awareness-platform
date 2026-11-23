"""Flask tracking and landing server.

Exposes the endpoints used by the simulation engine:

* ``GET /t/<token>``  — 1x1 open-tracking pixel.
* ``GET /c/<token>``  — click tracker that redirects to the landing page.
* ``GET /landing/<token>`` — simulated credential page.
* ``POST /submit/<token>`` — captures a submission, then shows training content.
* ``GET /training/<token>`` — the "you clicked a simulated phish" education page.
* ``GET /report/<token>`` — rewards users who correctly reported the email.

Every tracking route silently tolerates unknown tokens (returns 200) so that
invalid requests cannot be used to fingerprint which tokens are live.
"""

from __future__ import annotations

import base64
import logging

from flask import Flask, redirect, render_template, request, url_for

from ..storage.store import Store

logger = logging.getLogger("phishguard.landing")

TRANSPARENT_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)


def create_app(store: Store) -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config["JSON_SORT_KEYS"] = False

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/t/<token>")
    def track_open(token: str):
        delivery = store.get_delivery_by_token(token)
        if delivery:
            store.record_event(
                delivery["id"], "open", request.remote_addr,
                request.headers.get("User-Agent"),
            )
        return app.response_class(TRANSPARENT_GIF, mimetype="image/gif")

    @app.get("/c/<token>")
    def track_click(token: str):
        delivery = store.get_delivery_by_token(token)
        if delivery:
            store.record_event(
                delivery["id"], "click", request.remote_addr,
                request.headers.get("User-Agent"),
            )
            return redirect(url_for("landing", token=token))
        return redirect(url_for("landing", token=token))

    @app.get("/landing/<token>")
    def landing(token: str):
        return render_template("landing/login.html", token=token)

    @app.post("/submit/<token>")
    def submit(token: str):
        delivery = store.get_delivery_by_token(token)
        if delivery:
            store.record_event(
                delivery["id"], "submit", request.remote_addr,
                request.headers.get("User-Agent"),
            )
        return redirect(url_for("training", token=token))

    @app.get("/training/<token>")
    def training(token: str):
        return render_template("landing/training.html", token=token)

    @app.get("/report/<token>")
    def report(token: str):
        delivery = store.get_delivery_by_token(token)
        if delivery:
            store.record_event(
                delivery["id"], "report", request.remote_addr,
                request.headers.get("User-Agent"),
            )
        return render_template("landing/report.html")

    return app
