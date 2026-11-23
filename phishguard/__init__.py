"""PhishGuard — authorized phishing simulation and security awareness training.

PhishGuard helps security teams run controlled, consent-based phishing
simulations to measure and improve employee security awareness. It ships with:

* a campaign engine (SMTP delivery with per-target tracking tokens),
* a Flask tracking/landing server (open, click, and credential-submit capture),
* a heuristic phishing analyzer (the "defense" side, for awareness education),
* a lightweight reporting module (SQLite-backed metrics).

This tool is intended for authorized security awareness training only.
"""

__version__ = "1.0.0"
