"""Command-line administration."""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import func, select

from .config import settings
from .core.models.enums import Role
from .core.models.user import User
from .core.security.tokens import Scope, mint_token, validate_scopes
from .core.services.audit import Actor, record
from .core.services.auth import create_user
from .db import check_database, session_scope
from .logging import configure_logging

#: Commit interval for `enrich`. Small enough that an interrupted backfill
#: loses at most a few minutes of rate-limited work.
ENRICH_BATCH = 25


def cmd_create_admin(args: argparse.Namespace) -> int:
    email = args.email or input("Email: ").strip()
    display_name = args.name or input("Display name: ").strip()
    password = args.password or getpass.getpass("Password: ")
    if not args.password and password != getpass.getpass("Confirm password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    if len(password) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        return 1

    with session_scope() as db:
        try:
            user = create_user(
                db,
                email=email,
                display_name=display_name,
                password=password,
                role=Role.ADMIN,
                actor=Actor.system("cli"),
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Created admin: {user.email} ({user.id})")
    return 0


def cmd_create_token(args: argparse.Namespace) -> int:
    try:
        scopes = validate_scopes(args.scope or list(Scope.all()))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print(f"Valid scopes: {', '.join(Scope.all())}", file=sys.stderr)
        return 1

    from .core.models.user import ApiToken

    with session_scope() as db:
        minted = mint_token()
        token = ApiToken(
            name=args.name,
            token_prefix=minted.prefix,
            token_hash=minted.token_hash,
            scopes=scopes,
        )
        db.add(token)
        db.flush()
        record(
            db,
            actor=Actor.system("cli"),
            action="api_token.created",
            entity_type="api_token",
            entity_id=token.id,
            detail={"name": args.name, "scopes": scopes},
        )
        print(f"\n  Token: {minted.plaintext}\n")
        print("  This is shown ONCE and cannot be recovered. Store it now.")
        print(f"  Scopes: {', '.join(scopes)}\n")
    return 0


def cmd_list_users(_args: argparse.Namespace) -> int:
    with session_scope() as db:
        users = db.scalars(select(User).order_by(User.created_at)).all()
        if not users:
            print("No users. Create one with: advisory-hub create-admin")
            return 0
        print(f"{'EMAIL':<40} {'NAME':<24} {'ROLE':<9} ACTIVE")
        for u in users:
            print(f"{u.email:<40} {u.display_name:<24} {u.role.value:<9} {u.is_active}")
    return 0


def cmd_seed_sources(_args: argparse.Namespace) -> int:
    from .core.services.sources import seed_default_sources

    with session_scope() as db:
        created = seed_default_sources(db)
        for source in created:
            print(f"Created source: {source.short_code} — {source.name}")
        if not created:
            print("Sources already seeded.")
    return 0


def cmd_seed_vendor_aliases(_args: argparse.Namespace) -> int:
    from .core.services.vendor_alias import seed_vendor_aliases

    with session_scope() as db:
        created = seed_vendor_aliases(db)
        for alias in created:
            print(f"Created alias: {alias.alias!r} -> {alias.canonical_vendor}")
        if not created:
            print("Vendor aliases already seeded.")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest files directly, bypassing the watcher. Used for backfill."""
    from pathlib import Path

    from .ingest.pipeline import ingest_file
    from .ingest.watcher import MESSAGE_EXTENSIONS

    target = Path(args.path)
    if target.is_dir():
        files = sorted(p for p in target.rglob("*") if p.suffix.lower() in MESSAGE_EXTENSIONS)
    else:
        files = [target]
    if args.limit:
        files = files[: args.limit]
    if not files:
        print(f"No .msg/.eml files found under {target}", file=sys.stderr)
        return 1

    counts = {"INGESTED": 0, "DUPLICATE": 0, "FAILED": 0}
    for i, path in enumerate(files, 1):
        outcome = ingest_file(path)
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
        if outcome.status == "FAILED":
            print(f"  [{i}/{len(files)}] FAILED  {path.name[:64]}\n      {outcome.error}")
        elif args.verbose:
            ref = outcome.external_ref or "?"
            print(f"  [{i}/{len(files)}] {outcome.status:<9} {ref:<14} {path.name[:52]}")
        elif i % 25 == 0:
            print(f"  … {i}/{len(files)}")
    ingested, dupes, failed = counts["INGESTED"], counts["DUPLICATE"], counts["FAILED"]
    print(f"\ningested={ingested} duplicates={dupes} failed={failed}")
    return 0 if failed == 0 else 1


def cmd_watch(args: argparse.Namespace) -> int:
    """Poll the inbox once, or continuously."""
    import time

    from .ingest.pipeline import process_inbox

    if args.once:
        outcomes = process_inbox(limit=args.limit)
        print(f"processed {len(outcomes)} file(s)")
        return 0

    print(f"Watching {settings.inbox_path} every {settings.inbox_poll_seconds}s. Ctrl-C to stop.")
    try:
        while True:
            process_inbox(limit=args.limit)
            time.sleep(settings.inbox_poll_seconds)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def cmd_reparse(args: argparse.Namespace) -> int:
    """Re-derive parsed fields from stored blobs.

    Never touches status, assignee, comments, acknowledgement, or history —
    an analyst's work survives every parser upgrade.
    """
    from .core.services.reparse import reparse_advisories

    with session_scope() as db:
        report = reparse_advisories(
            db,
            since=args.since,
            parser_version_below=args.parser_version_below,
            dry_run=args.dry_run,
            limit=args.limit,
        )
    for line in report.lines:
        print(line)
    print(
        f"\n{'DRY RUN — no changes written' if args.dry_run else 'Updated'}: "
        f"{report.changed} changed, {report.unchanged} unchanged, {report.failed} failed"
    )
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    """Enrich CVEs from NVD.

    Runs in committed batches so a long backfill is genuinely resumable: NVD's
    anonymous rate limit makes a full corpus backfill ~50 minutes, and losing
    all of it to a Ctrl-C or a dropped connection would be unacceptable.
    """
    from .core.services.enrichment import enrich_pending, enrichment_summary

    totals = {
        "ok": 0,
        "not_found": 0,
        "errors": 0,
        "skipped": 0,
        "cached": 0,
        "cpe": 0,
        "rescored": 0,
    }
    remaining = args.limit
    interrupted = False

    try:
        while remaining is None or remaining > 0:
            size = ENRICH_BATCH if remaining is None else min(ENRICH_BATCH, remaining)
            with session_scope() as db:
                report = enrich_pending(db, limit=size, force=args.force)
            totals["ok"] += report.ok
            totals["not_found"] += report.not_found
            totals["errors"] += report.errors
            totals["skipped"] += report.skipped
            totals["cached"] += report.cached
            totals["cpe"] += report.cpe_rows
            totals["rescored"] += report.advisories_rescored
            for message in report.messages[:5]:
                print(f"  {message}")
            if report.attempted == 0 and report.skipped == 0:
                break
            if remaining is not None:
                remaining -= size
            print(
                f"  … ok={totals['ok']} not_found={totals['not_found']} "
                f"errors={totals['errors']} (committed)"
            )
    except KeyboardInterrupt:
        interrupted = True
        print("\ninterrupted — completed batches are committed; re-run to resume")

    print(
        f"\nok={totals['ok']} not_found={totals['not_found']} errors={totals['errors']} "
        f"skipped={totals['skipped']} (cache hits={totals['cached']})"
    )
    print(f"CPE rows written: {totals['cpe']}   advisories rescored: {totals['rescored']}")

    with session_scope() as db:
        print("\nenrichment status:")
        for key, value in sorted(enrichment_summary(db).items()):
            print(f"  {key:<20} {value}")
    return 130 if interrupted else 0


def cmd_check(_args: argparse.Namespace) -> int:
    from .core.storage.blobs import FilesystemBlobStore

    checks = {
        "database": check_database(),
        "blob volume writable": FilesystemBlobStore(settings.blob_root).healthcheck(),
        "inbox present": settings.inbox_path.is_dir(),
    }
    if checks["database"]:
        with session_scope() as db:
            checks["schema migrated"] = bool(
                db.scalar(select(func.count()).select_from(User.__table__)) is not None
            )
    for name, ok in checks.items():
        print(f"  [{'ok' if ok else 'FAIL'}] {name}")
    return 0 if all(checks.values()) else 1


def main() -> int:
    configure_logging(settings.log_level, "console")
    parser = argparse.ArgumentParser(prog="advisory-hub", description="Advisory Hub admin CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-admin", help="Create an administrator account")
    p.add_argument("--email")
    p.add_argument("--name")
    p.add_argument("--password", help="Prompted for if omitted (preferred)")
    p.set_defaults(func=cmd_create_admin)

    p = sub.add_parser("create-token", help="Mint a scoped API token")
    p.add_argument("--name", required=True)
    p.add_argument("--scope", action="append", help="Repeatable; defaults to all scopes")
    p.set_defaults(func=cmd_create_token)

    p = sub.add_parser("list-users", help="List user accounts")
    p.set_defaults(func=cmd_list_users)

    p = sub.add_parser("seed-sources", help="Seed the known regulator sources")
    p.set_defaults(func=cmd_seed_sources)

    p = sub.add_parser("seed-vendor-aliases", help="Seed the built-in vendor_alias rows")
    p.set_defaults(func=cmd_seed_vendor_aliases)

    p = sub.add_parser("ingest", help="Ingest a file or directory (backfill)")
    p.add_argument("path")
    p.add_argument("--limit", type=int)
    p.add_argument("--verbose", "-v", action="store_true")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("watch", help="Poll the inbox for new messages")
    p.add_argument("--once", action="store_true", help="Process one batch and exit")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("reparse", help="Re-derive parsed fields from stored blobs")
    p.add_argument("--since", help="ISO date, e.g. 2026-07-01")
    p.add_argument("--parser-version-below", type=int)
    p.add_argument("--limit", type=int)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_reparse)

    p = sub.add_parser("enrich", help="Enrich CVEs from NVD")
    p.add_argument("--limit", type=int, help="Maximum CVE rows to process")
    p.add_argument("--force", action="store_true", help="Re-enrich even fresh records")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("check", help="Verify database, storage, and configuration")
    p.set_defaults(func=cmd_check)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
