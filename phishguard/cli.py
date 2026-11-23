"""Command-line interface for PhishGuard."""

from __future__ import annotations

import argparse
import logging
import re
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Optional

from .config import load_config
from .detection import analyzer
from .engine import campaign as campaign_engine
from .engine import templates
from .landing.app import create_app
from .reporting import report as report_mod
from .storage.store import Store

logger = logging.getLogger("phishguard")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )


def _store(args: argparse.Namespace) -> Store:
    return Store(args.config.database.path)


def cmd_init(args: argparse.Namespace) -> int:
    cfg = load_config(args.config_path)
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    example_cfg = """smtp:
  host: smtp.example.com
  port: 587
  username: ""
  password: ""
  use_tls: true
  from_email: security@example.com
  from_name: "IT Security Team"

server:
  host: 127.0.0.1
  port: 5000
  base_url: "http://127.0.0.1:5000"

database:
  path: "data/phishguard.db"

dry_run: true
"""
    if not Path(args.config_path).exists():
        Path(args.config_path).write_text(example_cfg, encoding="utf-8")
        print(f"wrote {args.config_path}")
    else:
        print(f"{args.config_path} already exists, leaving it untouched")

    targets_example = Path("data/targets.example.csv")
    if not targets_example.exists():
        targets_example.write_text(
            "email,name,department\n"
            "alice@example.com,Alice Smith,Finance\n"
            "bob@example.com,Bob Jones,Engineering\n"
            "carol@example.com,Carol Lee,Human Resources\n",
            encoding="utf-8",
        )
        print(f"wrote {targets_example}")

    print("\nPhishGuard initialized. Next steps:")
    print("  1. Edit config.yaml (set smtp host + credentials, or leave dry_run: true)")
    print("  2. Copy data/targets.example.csv to data/targets.csv and edit")
    print("  3. Run: python -m phishguard campaign send --name demo --template password_reset --targets data/targets.csv")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    if args.target == "url":
        result = analyzer.analyze_url(args.value)
    else:
        result = _analyze_email_file(args.value)
    print(f"Verdict: {result.verdict} (score {result.score}/100)")
    for finding in result.findings:
        print(f"  [{finding.severity:<6}] {finding.message}")
    return 0


def _analyze_email_file(path: str):
    raw = Path(path).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = {k: msg[k] for k in msg.keys()}
    body = ""
    links = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content() or ""
            if part.get_content_type() == "text/html":
                html = part.get_content() or ""
                links.extend(re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE))
    else:
        body = msg.get_content() or ""
        if msg.get_content_type() == "text/html":
            links.extend(re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE))
    return analyzer.analyze_email(headers, body, links)


def cmd_campaign_send(args: argparse.Namespace) -> int:
    store = _store(args)
    summary = campaign_engine.run_campaign(
        cfg=args.config,
        store=store,
        campaign_name=args.name,
        template_name=args.template,
        targets_file=args.targets,
        dry_run=args.dry_run,
    )
    print(f"Campaign #{summary['campaign_id']} '{summary['campaign_name']}' "
          f"({summary['template']})")
    print(f"  targets={summary['targets']} delivered={summary['delivered']} "
          f"failed={summary['failed']} dry_run={summary['dry_run']}")
    print(f"\nRun the tracking server, then view results:")
    print(f"  python -m phishguard server")
    print(f"  python -m phishguard report {summary['campaign_id']}")
    return 0


def cmd_campaign_list(args: argparse.Namespace) -> int:
    store = _store(args)
    campaigns = store.list_campaigns()
    if not campaigns:
        print("No campaigns yet.")
        return 0
    print(f"{'ID':<5}{'Name':<30}{'Template':<20}{'Status':<10}")
    for c in campaigns:
        print(f"{c['id']:<5}{c['name']:<30}{c['template']:<20}{c['status']:<10}")
    return 0


def cmd_server(args: argparse.Namespace) -> int:
    cfg = args.config
    store = _store(args)
    app = create_app(store)
    print(f"Starting tracking server at {cfg.server.base_url}")
    print("Endpoints: /t/<token> (pixel)  /c/<token> (click)  /landing/<token> (login)")
    app.run(host=cfg.server.host, port=cfg.server.port, debug=args.debug)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = _store(args)
    summary = report_mod.campaign_summary(store, args.campaign_id)
    if args.format == "text":
        print(report_mod.to_text(summary))
    elif args.format == "json":
        print(report_mod.to_json(summary))
    elif args.format == "csv":
        print(report_mod.to_csv(summary))
    elif args.format == "html":
        out = Path(f"report_{args.campaign_id}.html")
        out.write_text(report_mod.to_html(summary), encoding="utf-8")
        print(f"wrote {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="Authorized phishing simulation and security awareness training.",
    )
    parser.add_argument("--config", dest="config_path", default="config.yaml",
                        help="path to config.yaml (default: config.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create example config and targets")
    p_init.set_defaults(func=cmd_init)

    p_analyze = sub.add_parser("analyze", help="analyze a URL or email for phishing indicators")
    p_analyze.add_argument("target", choices=["url", "email"])
    p_analyze.add_argument("value", help="URL to inspect, or path to a .eml file")
    p_analyze.set_defaults(func=cmd_analyze)

    p_campaign = sub.add_parser("campaign", help="campaign operations")
    campaign_sub = p_campaign.add_subparsers(dest="campaign_command", required=True)

    p_send = campaign_sub.add_parser("send", help="run a phishing simulation campaign")
    p_send.add_argument("--name", required=True, help="campaign name")
    p_send.add_argument("--template", required=True, choices=templates.list_templates())
    p_send.add_argument("--targets", required=True, help="path to targets CSV")
    p_send.add_argument("--send", dest="dry_run", action="store_false",
                        help="actually send email (default is dry-run)")
    p_send.set_defaults(dry_run=True, func=cmd_campaign_send)

    p_list = campaign_sub.add_parser("list", help="list campaigns")
    p_list.set_defaults(func=cmd_campaign_list)

    p_server = sub.add_parser("server", help="run the tracking/landing server")
    p_server.add_argument("--debug", action="store_true")
    p_server.set_defaults(func=cmd_server)

    p_report = sub.add_parser("report", help="generate a campaign report")
    p_report.add_argument("campaign_id", type=int)
    p_report.add_argument("--format", choices=["text", "json", "csv", "html"], default="text")
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    args.config = load_config(args.config_path)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
