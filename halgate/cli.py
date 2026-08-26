"""CLI entry point: argparse subcommands + interactive REPL."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

from .config import load_config
from .errors import ConfigError

BANNER = "halgate security harness"


def _make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="halgate",
        description="Single-operator local security-research AI halgate.")
    sub = p.add_subparsers(dest="command")

    # top-level subcommands (stored for nested sub-commands)
    sub.add_parser("run", help="Start a session (default)")
    sub.add_parser("tui", help="Start a session with textual TUI")
    ses_parser = sub.add_parser("session", help="Session management")
    audit_parser = sub.add_parser("audit", help="Audit log commands")
    mem_parser = sub.add_parser("memory", help="Memory commands")
    sec_parser = sub.add_parser("secret", help="Credential keystore commands")
    key_parser = sub.add_parser("key", help="Native encryption-key commands")
    ev_parser = sub.add_parser("evidence", help="Evidence commands")
    fin_parser = sub.add_parser("finding", help="Finding commands")
    inv_parser = sub.add_parser("inventory", help="Inventory commands")
    bud_parser = sub.add_parser("budget", help="Budget status")
    bud_parser.add_argument("--engagement", default=None)

    # main-level flags
    p.add_argument("--config", default=None, help="Path to config.yaml")
    p.add_argument("--pkg", default=None, help="Default scope package name")
    p.add_argument("--llm", default=None, help="Active LLM endpoint id")
    p.add_argument("--name", default=None, help="Session name")
    p.add_argument("--no-tui", action="store_true",
                   help="Force CLI mode even if TUI available")
    p.add_argument("--resume", default=None, help="Resume a session by id")
    p.add_argument("--latest", action="store_true",
                   help="Resume the most recent session")
    p.add_argument("--add", action="append", default=[],
                   help='Add engagement: "label:target[:package]" (repeatable)')
    p.add_argument("--dry-run", action="store_true",
                   help="Validation-only mode: no execution")

    # audit sub-subcommands
    audit_sp = audit_parser.add_subparsers(dest="audit_cmd")
    ar = audit_sp.add_parser("replay")
    ar.add_argument("session_id")
    ar.add_argument("--event", default=None)
    ar.add_argument("--tool", default=None)
    av = audit_sp.add_parser("verify")
    av.add_argument("session_id")
    as_ = audit_sp.add_parser("search")
    as_.add_argument("session_id")
    as_.add_argument("--event", default=None)
    as_.add_argument("--key", default=None)
    ad = audit_sp.add_parser("decrypt")
    ad.add_argument("session_id")
    ad.add_argument("--seq", type=int, required=True,
                    help="Audit event sequence number to decrypt")

    key_sp = key_parser.add_subparsers(dest="key_cmd")
    key_sp.add_parser("init", help="Create a native key and display its recovery phrase")
    kb = key_sp.add_parser("backup", help="Export the encrypted key envelope")
    kb.add_argument("path")
    kr = key_sp.add_parser("restore", help="Restore an encrypted key envelope")
    kr.add_argument("path")
    kr.add_argument("--replace", action="store_true")

    # memory sub-subcommands
    mem_sp = mem_parser.add_subparsers(dest="memory_cmd")
    ml = mem_sp.add_parser("list")
    ml.add_argument("--subject", default=None, choices=["target", "self"])
    ms = mem_sp.add_parser("search")
    ms.add_argument("query")
    me = mem_sp.add_parser("edit")
    me.add_argument("mem_id")
    me.add_argument("text")
    mp = mem_sp.add_parser("pin")
    mp.add_argument("mem_id")
    mu = mem_sp.add_parser("unpin")
    mu.add_argument("mem_id")

    # secret sub-subcommands
    sec_sp = sec_parser.add_subparsers(dest="secret_cmd")
    sec_sp.add_parser("list")
    sr = sec_sp.add_parser("reveal")
    sr.add_argument("cred_id")
    ss = sec_sp.add_parser("store")
    ss.add_argument("--type", default="generic", help="Credential type label")
    ss.add_argument("--engagement", default=None, help="Engagement id (optional)")

    # evidence sub-subcommands
    ev_sp = ev_parser.add_subparsers(dest="evidence_cmd")
    es = ev_sp.add_parser("show")
    es.add_argument("ref")
    ei = ev_sp.add_parser("import")
    ei.add_argument("fmt", choices=["nmap", "nuclei", "burp", "sarif"])
    ei.add_argument("path")
    ei.add_argument("--engagement", required=True)

    # finding sub-subcommands
    fin_sp = fin_parser.add_subparsers(dest="finding_cmd")
    fin_sp.add_parser("list").add_argument("--status", default=None)
    fe = fin_sp.add_parser("export")
    fe.add_argument("--format", default="markdown",
                    choices=["markdown", "json", "sarif"])
    fe.add_argument("--out", required=True)

    # inventory sub-subcommands
    inv_sp = inv_parser.add_subparsers(dest="inventory_cmd")
    inv_d = inv_sp.add_parser("diff")
    inv_d.add_argument("engagement_id")
    inv_d.add_argument("--against", default=None)

    # session sub-subcommands
    ses_sp = ses_parser.add_subparsers(dest="session_cmd")
    ses_sp.add_parser("list")
    sshow = ses_sp.add_parser("show")
    sshow.add_argument("session_id")

    return p


def main() -> int:
    parser = _make_parser()
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if args.pkg:
        if args.pkg not in config.packages:
            print(f"ERROR: unknown scope package: {args.pkg}", file=sys.stderr)
            return 1
        config.scope.package = args.pkg
    if args.llm:
        config.llm.active = args.llm
    if args.dry_run:
        config.safety.dry_run = True

    # subcommand dispatch
    if args.command in ("audit", "memory", "secret", "key", "evidence",
                        "finding", "inventory", "budget", "session"):
        return _handle_subcommand(args, config)

    # main / tui / run: start a session
    from .halgate import Halgate
    from .instance import instance_id

    restored = None
    if args.resume or args.latest:
        from .sessions.checkpoint import SessionCheckpoint
        sid = args.resume or SessionCheckpoint.latest(config.sessions.dir)
        if sid:
            try:
                restored = SessionCheckpoint.load(config.sessions.dir, sid)
            except FileNotFoundError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 1
    engagements = list(restored.engagements) if restored else _parse_engagements(args, config)
    if restored:
        settings = restored.session_settings
        if "forensic_enabled" in settings:
            config.audit.forensic_enabled = bool(settings["forensic_enabled"])
        if "retention_days" in settings:
            config.evidence.retention_days = int(settings["retention_days"])
        if "chat_width_pct" in settings:
            config.tui.chat_width_pct = int(settings["chat_width_pct"])
    h = Halgate(config, engagements,
                session_id=restored.session_id if restored else None,
                instance_id=instance_id(), resumed=bool(restored))

    # Resume
    if restored:
        h.messages = restored.messages
        print(f"Resumed session: {restored.session_id} "
              f"({len(h.messages)} messages)")

    if not args.no_tui and has_tty():
        if args.command == "tui" or os.environ.get("TERM"):
            from .tui import HalgateApp
            app = HalgateApp(h)
            app.run()
            return 0

    return _run_cli_mode(h)


def _parse_engagements(args, config) -> list:
    from .scope import Engagement, new_engagement_id
    engagements = []
    pkg = args.pkg or config.scope.package or "defensive"
    for i, spec in enumerate(args.add):
        parts = spec.split(":", 2)
        if len(parts) == 3:
            label, target, pkg_ = parts
        elif len(parts) == 2:
            label, target = parts
            pkg_ = pkg
        else:
            print(f"ERROR: invalid --add format: {spec!r} "
                  f"(expected 'label:target[:package]')", file=sys.stderr)
            continue
        eid = new_engagement_id()
        if pkg_ not in config.packages:
            print(f"ERROR: unknown scope package '{pkg_}'", file=sys.stderr)
            continue
        engagements.append(Engagement(id=eid, label=label, target=target, package=pkg_))
    return engagements


def _onboarding_wizard(h) -> None:
    """Interactive wizard shown when no engagements are active."""
    from .scope import Engagement, new_engagement_id
    from .sessions.checkpoint import SessionCheckpoint

    sessions = SessionCheckpoint.list_sessions(h.config.sessions.dir)
    has_sessions = bool(sessions)

    print("\n" + "=" * 50)
    print("  No active engagement. Choose one:")
    print("=" * 50)
    print("  [1]  New engagement")
    if has_sessions:
        print(f"  [2]  Continue previous session "
              f"(latest: {sessions[0]['name']})")
        print("  [4]  Manage sessions (delete)")
    print("  [3]  Skip for now (add later via /engagement add)")
    print("=" * 50)

    choices = ["1", "3"]
    if has_sessions:
        choices.insert(1, "2")
        choices.append("4")
    prompt = "Choice [" + "/".join(choices) + "] (default 1): "

    choice = input(prompt).strip() or "1"

    if choice == "1":
        print("\n--- New Engagement ---")
        label = input("Label (e.g. 'Staging Server'): ").strip() or "Target"
        target = input("Target (IP, CIDR, or hostname): ").strip()
        if not target:
            print("Cancelled: no target provided.")
            return

        pkgs = list(h.config.packages.keys())
        print("\nAvailable scope packages:")
        for i, name in enumerate(pkgs, 1):
            default_marker = " *" if name == h.config.scope.package else ""
            print(f"  [{i}]  {name}{default_marker}")
        default_idx = (pkgs.index(h.config.scope.package)
                       if h.config.scope.package in pkgs else 0) + 1

        pkg_choice = input(f"Package [1-{len(pkgs)}] (default {default_idx}): "
                           ).strip() or str(default_idx)
        try:
            pkg_idx = int(pkg_choice) - 1
            pkg_name = pkgs[pkg_idx] if 0 <= pkg_idx < len(pkgs) else pkgs[0]
        except (ValueError, IndexError):
            pkg_name = pkgs[0]

        eid = new_engagement_id()
        eng = Engagement(id=eid, label=label, target=target, package=pkg_name)
        h.add_engagement(eng)
        print(f"\n  Added: {eid}: {label} ({target}, {pkg_name})")

    elif choice == "2" and has_sessions:
        print("\nAvailable sessions:")
        for i, s in enumerate(sessions[:5], 1):
            engs = ", ".join(s.get("engagements", [])) or "no target"
            print(f"  [{i}]  {s['name']}")
            print(f"       {engs}")
            print(f"       {s['created'][:19]}  {s['turns']} turns")
        print("       [c]  Cancel")
        sel = input(
            f"Select [1-{min(len(sessions), 5)}/c]: ").strip().lower() or "1"
        if sel in ("c", "cancel", "q", ""):
            print("  Cancelled. Use /engagement add label:target[:package] later.")
            return
        try:
            idx = int(sel) - 1
        except ValueError:
            idx = 0
        if 0 <= idx < len(sessions):
            restored = SessionCheckpoint.load(
                h.config.sessions.dir, sessions[idx]["id"])
            h.restore_session(restored)
            engs = ", ".join(
                f"{e.label} ({e.target})" for e in restored.engagements)
            print(f"\n  Resumed: {restored.name}")
            print(f"  Target:  {engs}")
            print(f"  Messages: {len(h.messages)}")
        else:
            print("  Invalid selection. Use /engagement add later.")

    elif choice == "4" and has_sessions:
        print("\n--- Manage Sessions ---")
        for i, s in enumerate(sessions[:10], 1):
            engs = ", ".join(s.get("engagements", [])) or "no target"
            print(f"  [{i}]  {s['name']}  target: {engs}")
            print(f"       {s['created'][:19]}  {s['turns']} turns  "
                  f"id: {s['id']}")
        print()
        action = input("Action [delete, or blank to cancel]: ").strip()
        if not action:
            print("  Cancelled.")
            return
        action = action.lower()
        if action.startswith("del"):
            sel = input("Session number to delete: ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(sessions[:10]):
                sid = sessions[int(sel) - 1]["id"]
                confirm = input(f"  Delete {sessions[int(sel)-1]['name']}? "
                                f"[y/N]: ").strip().lower()
                if confirm == "y":
                    if SessionCheckpoint.delete(h.config.sessions.dir, sid):
                        print(f"  Deleted: {sid}")
                    else:
                        print(f"  Not found: {sid}")

    else:
        print("  Skipped. Use /engagement add label:target[:package] later.")


def _run_cli_mode(h) -> int:
    """Simple CLI prompt loop."""
    from .sessions.checkpoint import SessionCheckpoint
    sessions = SessionCheckpoint.list_sessions(h.config.sessions.dir)

    print(f"\n{BANNER}")
    print(f"Session: {h.session_id}")
    if h.engagements:
        for e in h.engagements:
            print(f"  {e.id}: {e.label} ({e.target}, {e.package})")
        if sessions:
            print(f"  ({len(sessions)} saved session(s) available — "
                  f"'/sessions' to switch)")
    else:
        if sessions:
            latest = sessions[0]
            engs = ", ".join(latest.get("engagements", [])) or "no target"
            print(f"  (latest saved: {latest['name']} → {engs})")
    print(f"LLM: {h.router.active_endpoint.model} @ "
          f"{h.router.active_endpoint.base_url}")
    if h.config.safety.dry_run:
        print("Mode: DRY-RUN (no execution)")

    if not h.engagements:
        _onboarding_wizard(h)

    print("\nType your request ('/quit' to exit, /help for commands)\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        while True:
            try:
                user_input = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not user_input:
                continue
            if user_input.startswith("/"):
                cmd_res = _handle_command(h, user_input)
                if cmd_res is True:
                    break
                continue
            try:
                result = loop.run_until_complete(h.run(user_input))
                print(f"\n[Agent] {result}\n")
                print(h.tracker.status_line(), "\n")
            except Exception as e:
                print(f"[ERROR] {e}", file=sys.stderr)
    finally:
        try:
            h.checkpoint()
        except Exception:
            pass
        loop.close()
    return 0


def _handle_command(h, cmd: str) -> bool:
    """Process a /-command. Returns True if it means 'quit'."""
    parts = cmd.strip().split(None, 1)
    name = parts[0].lstrip("/").lower()
    arg = parts[1] if len(parts) > 1 else ""

    if name == "quit":
        print("Session saved. Bye.")
        return True
    elif name == "help":
        print("/panes /send /recall /compact /engagement /reveal "
              "/kill /checkpoint /status /dry-run /budget /panic "
              "/resume-actions /engagement add label:target[:package] "
              "/sessions /sessions pick /sessions delete <id> "
              "/resume <id> "
              "/quit")
    elif name == "sessions":
        from .sessions.checkpoint import SessionCheckpoint
        sessions = SessionCheckpoint.list_sessions(h.config.sessions.dir)

        # Sub-command: delete
        sub = arg.strip().split(None, 1) if arg.strip() else []
        if sub and sub[0].lower() == "delete":
            sid = sub[1].strip() if len(sub) > 1 else ""
            if not sid:
                sid = input("Session id to delete: ").strip()
            if not sid:
                # try picking by number
                print("\nSessions to delete:")
                for i, s in enumerate(sessions[:10], 1):
                    engs = ", ".join(s.get("engagements", [])) or "no target"
                    print(f"  [{i}]  {s['name']}  target: {engs}")
                sel = input("Number: ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(sessions[:10]):
                    sid = sessions[int(sel) - 1]["id"]
            if sid:
                if SessionCheckpoint.delete(h.config.sessions.dir, sid):
                    print(f"  Deleted session: {sid}")
                else:
                    print(f"  Not found: {sid}")
            return False

        # Default: list + optional pick-to-resume
        if not sessions:
            print("No saved sessions.")
        else:
            for i, s in enumerate(sessions[:10], 1):
                engs = ", ".join(s.get("engagements", [])) or "no target"
                print(f"  [{i}]  {s['name']}  (id: {s['id']})")
                print(f"       target: {engs}")
                print(f"       {s['created'][:19]}  "
                      f"{s['turns']} turns  llm:{s.get('llm_id', '?')}")
            if arg.strip().lower() in ("pick", "select", "resume"):
                sel = input("Resume session [1-10, or blank to cancel]: "
                            ).strip()
                if sel.isdigit() and 1 <= int(sel) <= len(sessions[:10]):
                    idx = int(sel) - 1
                    sid = sessions[idx]["id"]
                    restored = SessionCheckpoint.load(
                        h.config.sessions.dir, sid)
                    h.restore_session(restored)
                    print(f"  Resumed: {restored.name} "
                          f"({len(restored.messages)} messages, "
                          f"{len(restored.engagements)} engagement(s))")
            print("  Actions: /sessions pick | /sessions delete <id>")
    elif name == "resume":
        if not arg:
            print("/resume requires a session id. Use /sessions to list.")
        else:
            from .sessions.checkpoint import SessionCheckpoint
            try:
                restored = SessionCheckpoint.load(
                    h.config.sessions.dir, arg)
            except FileNotFoundError:
                print(f"No session found: {arg}")
            else:
                h.restore_session(restored)
                engs = ", ".join(
                    f"{e.label} ({e.target})" for e in restored.engagements)
                print(f"  Resumed: {restored.name}")
                print(f"  Target: {engs}")
                print(f"  Messages restored: {len(h.messages)}")
    elif name == "status":
        s = h.status
        print(json.dumps(s, indent=2, default=str))
    elif name == "checkpoint":
        h.checkpoint()
        print(f"Checkpoint saved: {h.session_id}")
    elif name == "compact":
        n = int(arg) if arg.isdigit() else 1
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            msg = loop.run_until_complete(h.compact(n))
            print(msg)
        finally:
            loop.close()
    elif name == "dry-run":
        if arg == "on":
            h.config.safety.dry_run = True
            print("Dry-run ON: actions will be planned but not executed.")
        elif arg == "off":
            h.config.safety.dry_run = False
            print("Dry-run OFF.")
        else:
            print(f"Current: {'ON' if h.config.safety.dry_run else 'OFF'}")
    elif name == "panic":
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(h.safety.panic())
            print(f"Panic: {json.dumps(result, default=str)}")
        finally:
            loop.close()
    elif name == "resume-actions":
        h.safety.resume_actions()
        print("Actions unlocked.")
    elif name == "budget":
        if arg:
            print(json.dumps(h.budgets.status(arg), indent=2, default=str))
        else:
            print(json.dumps(h.budgets.all_status(), indent=2, default=str))
    elif name == "panes":
        for p in h.process_mgr.list():
            print(f"  {p['id']} {p['name']:12s} {p['status']:8s} {p['cmd']}")
    elif name == "recall":
        r = h.memory.recall(query=arg)
        for m in r.get("memories", []):
            print(f"  [{m.get('id')}] ({m.get('confidence'):.0%}) "
                  f"{m.get('text')}")
    elif name == "engagement":
        sub = arg.split(None, 1) if arg else ["list", ""]
        if sub[0] == "list" or not arg:
            for e in h.engagements:
                print(f"  {e.id}: {e.label} ({e.target}, {e.package}, {e.status})")
        elif sub[0] == "add" and len(sub) > 1:
            parts = sub[1].split(":", 2)
            if len(parts) == 3:
                label, target = parts[0], parts[1]
                pkg_name = parts[2]
            elif len(parts) == 2:
                label, target = parts[0], parts[1]
                pkg_name = h.config.scope.package or "defensive"
            else:
                print("Usage: /engagement add label:target[:package]")
                return False
            if pkg_name not in h.config.packages:
                print(f"ERROR: unknown scope package '{pkg_name}'")
                return False
            from .scope import Engagement, new_engagement_id
            eid = new_engagement_id()
            eng = Engagement(id=eid, label=label, target=target, package=pkg_name)
            h.add_engagement(eng)
            print(f"Added {eid}: {label} ({target}, {pkg_name})")
        elif sub[0] == "pause" and sub[1]:
            for e in h.engagements:
                if e.id == sub[1]:
                    e.status = "paused"
                    break
        elif sub[0] == "resume" and sub[1]:
            for e in h.engagements:
                if e.id == sub[1]:
                    e.status = "active"
                    break
        elif sub[0] == "claims":
            parts = sub[1].split(None, 2) if len(sub) > 1 else []
            if len(parts) < 3:
                for e in h.engagements:
                    ext = ", ".join(e.jwt_claim_extensions) or "(none)"
                    print(f"  {e.id}: {e.label} — extensions: [{ext}]")
                print("Usage: /engagement claims <id> add|remove <keys...>")
            else:
                eng_id, action = parts[0], parts[1].lower()
                keys = parts[2].split() if len(parts) > 2 else []
                eng = next((e for e in h.engagements if e.id == eng_id), None)
                if eng is None:
                    print(f"ERROR: unknown engagement '{eng_id}'")
                elif action == "add":
                    new_ext = set(eng.jwt_claim_extensions)
                    added = []
                    for k in keys:
                        if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,63}", k) \
                                and k not in ("iat", "exp", "nbf"):
                            if k not in new_ext:
                                added.append(k)
                            new_ext.add(k)
                        else:
                            print(f"  Warning: invalid claim key '{k}', skipped")
                    pkg_claims = set(h.config.packages.get(eng.package,
                        type("P", (), {"jwt_allowed_claims": []})()).jwt_allowed_claims) \
                        if eng.package in h.config.packages else set()
                    if len(new_ext | pkg_claims) > 16:
                        print(f"ERROR: total claim set would exceed 16 "
                              f"({len(new_ext | pkg_claims)} > 16)")
                    else:
                        eng.jwt_claim_extensions = tuple(sorted(new_ext))
                        print(f"Added {added or '(none new)'} to "
                              f"{eng_id} claim extensions")
                elif action == "remove":
                    before = set(eng.jwt_claim_extensions)
                    after = {k for k in before if k not in keys}
                    removed = before - after
                    eng.jwt_claim_extensions = tuple(sorted(after))
                    print(f"Removed {removed or '(none)'} from "
                          f"{eng_id} claim extensions")
                else:
                    print("Usage: /engagement claims <id> add|remove <keys...>")
    elif name == "full":
        print(f"(showing full output for call {arg})")
    elif name == "reveal":
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            value = loop.run_until_complete(
                h._keystore.reveal(arg))
            if value:
                print(value)
            else:
                print("Not found.")
        finally:
            loop.close()
    else:
        print(f"Unknown command: /{name}. Type /help.")
    return False


def _handle_subcommand(args, config) -> int:
    """Handle non-interactive CLI subcommands."""
    from .instance import instance_id

    instance = instance_id()

    if args.command == "audit":
        _handle_audit(args, config, instance)
        return 0
    elif args.command == "memory":
        _handle_memory(args, config, instance)
        return 0
    elif args.command == "secret":
        _handle_secret(args, config, instance)
        return 0
    elif args.command == "key":
        _handle_key(args, config)
        return 0
    elif args.command == "evidence":
        _handle_evidence(args, config)
        return 0
    elif args.command == "finding":
        _handle_finding(args, config)
        return 0
    elif args.command == "inventory":
        _handle_inventory(args, config)
        return 0
    elif args.command == "budget":
        print("Use budget within an active session.")
        return 0
    elif args.command == "session":
        _handle_session(args, config)
        return 0
    return 0


def _handle_audit(args, config, instance) -> None:
    from .audit.replay import (decrypt_payload, replay, session_log_path,
                               search, verify)
    sid = args.session_id
    if not sid:
        print("No session id given for audit command.")
        return
    audit_dir = str(config.audit.dir)
    try:
        log_path = session_log_path(audit_dir, instance, sid)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return
    if args.audit_cmd == "replay":
        events = replay(log_path, event_filter=args.event)
        for e in events:
            print(json.dumps(e, indent=2, default=str))
    elif args.audit_cmd == "verify":
        ok, broken_seq, msg = verify(log_path)
        print(f"Chain verified: {ok}")
        if not ok:
            print(msg)
    elif args.audit_cmd == "search":
        events = search(log_path, event=args.event or "")
        for e in events:
            print(json.dumps(e, indent=2, default=str))
    elif args.audit_cmd == "decrypt":
        from .errors import EncryptionError
        from .audit.logger import AuditLogger
        audit_log = AuditLogger(config.audit, sid, instance)
        try:
            plaintext = asyncio.run(decrypt_payload(
                log_path, config.audit, instance, sid, args.seq, audit_log))
        except EncryptionError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return
        print(plaintext)


def _handle_key(args, config) -> None:
    """Manage the portable encrypted root-key envelope."""
    from .crypto import NativeCrypto
    from .errors import EncryptionError
    key_path = config.audit.encryption_key_file
    try:
        if args.key_cmd == "init":
            phrase = NativeCrypto.initialize(key_path)
            print("Store this recovery phrase offline; it will not be shown again:")
            print(phrase)
        elif args.key_cmd == "backup":
            NativeCrypto.backup(key_path, args.path)
            print(f"Encrypted key backup written to {args.path}")
        elif args.key_cmd == "restore":
            import getpass
            phrase = getpass.getpass("Halgate recovery phrase: ")
            NativeCrypto.restore(args.path, key_path, phrase, args.replace)
            print("Encrypted key restored.")
        else:
            print("Specify key init, key backup, or key restore.", file=sys.stderr)
    except EncryptionError as e:
        print(f"ERROR: {e}", file=sys.stderr)


def _handle_memory(args, config, instance) -> None:
    from .memory.store import MemoryStore
    store = MemoryStore(config.memory, instance)
    if args.memory_cmd == "list":
        entries = store.read_long_term()
        for e in entries:
            pin = "[PIN] " if e.get("pinned") else ""
            print(f"  {e.get('id')} {pin}({e.get('confidence'):.0%}) "
                  f"[{e.get('category')}] {e.get('text')[:80]}")
        print(f"Total: {len(entries)}")
    elif args.memory_cmd == "search":
        r = store.recall(query=args.query)
        for m in r.get("memories", []):
            print(f"  [{m.get('id')}] {m.get('text')}")
    elif args.memory_cmd == "edit":
        r = store.edit(args.mem_id, args.text)
        print(json.dumps(r))
    elif args.memory_cmd == "pin":
        r = store.pin(args.mem_id, True)
        print(json.dumps(r))
    elif args.memory_cmd == "unpin":
        r = store.pin(args.mem_id, False)
        print(json.dumps(r))


def _handle_secret(args, config, instance) -> None:
    from .memory.keystore import KeyStore
    ks = KeyStore(config.audit, instance)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        if args.secret_cmd == "list":
            if not ks._path.exists():
                print("No stored secrets.")
                return
            with ks._path.open() as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    print(f"  {obj.get('id')} ({obj.get('type')}) "
                          f"found_in={obj.get('found_in')}")
        elif args.secret_cmd == "reveal":
            val = loop.run_until_complete(ks.reveal(args.cred_id))
            if val:
                print(val)
            else:
                print("Not found or decryption failed.")
        elif args.secret_cmd == "store":
            import getpass
            value = getpass.getpass("Secret value: ")
            if not value:
                print("ERROR: empty secret value", file=sys.stderr)
                return
            cred_id = loop.run_until_complete(
                ks.store(args.type, value, "operator_store", args.engagement))
            print(cred_id)
    finally:
        loop.close()


def _handle_evidence(args, config) -> None:
    if args.evidence_cmd == "show":
        # needs session context; minimal standalone show
        from .evidence.store import EvidenceStore
        ev_dir = Path(config.evidence.dir)
        sessions = list(ev_dir.iterdir()) if ev_dir.exists() else []
        for s in sessions:
            store = EvidenceStore(config.evidence, s.name)
            result = store.show(args.ref)
            if "error" not in result:
                print(json.dumps(result, indent=2, default=str))
                return
        print(f"Evidence {args.ref} not found.")
    elif args.evidence_cmd == "import":
        print("Evidence import requires an active session. Use /import in TUI "
              "or pass --engagement with a session_id.")


def _handle_finding(args, config) -> None:
    ev_dir = Path(config.evidence.dir)
    if not ev_dir.exists():
        print("No evidence directory. Run a session first.")
        return
    from .evidence.store import EvidenceStore
    from .evidence.findings import FindingStore
    sessions = list(ev_dir.iterdir())
    for s in sessions[-1:]:
        store = EvidenceStore(config.evidence, s.name)
        fs = FindingStore(store, s.name)
        if args.finding_cmd == "list":
            findings = fs.list_all(args.status)
            for f in findings:
                print(f"  {f['id']} [{f['severity']}] ({f['status']}) "
                      f"{f['title']}")
            print(f"Total: {len(findings)}")
        elif args.finding_cmd == "export":
            if args.format == "markdown":
                content = fs.export_markdown(args.status)
            elif args.format == "json":
                content = fs.export_json(args.status)
            else:
                content = fs.export_sarif(args.status)
            Path(args.out).write_text(content)
            print(f"Exported {len(fs.list_all(args.status))} findings to "
                  f"{args.out}")


def _handle_inventory(args, config) -> None:
    ev_dir = Path(config.evidence.dir)
    if not ev_dir.exists():
        print("No evidence directory.")
        return
    from .evidence.inventory import InventoryStore
    inv_dir = ev_dir
    if args.inventory_cmd == "diff":
        inv = InventoryStore(inv_dir, "cli")
        result = inv.diff(args.engagement_id, args.against)
        print(json.dumps(result, indent=2, default=str))


def _handle_session(args, config) -> None:
    from .sessions.checkpoint import SessionCheckpoint
    if args.session_cmd == "list":
        sessions = SessionCheckpoint.list_sessions(config.sessions.dir)
        for s in sessions:
            print(f"  {s.get('id')}  {s.get('name', ''):40s} "
                  f"{s.get('created', '')}")
    elif args.session_cmd == "show":
        r = SessionCheckpoint.load(config.sessions.dir, args.session_id)
        print(f"Session: {r.session_id}")
        print(f"Name: {r.name}")
        print(f"Messages: {len(r.messages)}")
        print(f"LLM: {r.llm_id}")
        eng_ids = [e.id for e in r.engagements]
        print(f"Engagements: {eng_ids}")


def has_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


if __name__ == "__main__":
    sys.exit(main())
