"""Command line interface.

Three modes, in order of how much time each saves:

  map     enumerate every entry point in a plugin directory — the triage view
  audit   rank findings for one plugin (local directory, or slug[@version])
  diff    guard-set regression between two releases of the same plugin

`diff` is the one that scales. Reviewing changed LINES produces noise: refactors,
i18n, asset churn. Comparing the entry-point GRAPH between releases produces a
short list of things that are actually new or actually weaker — a new
unauthenticated handler, a permission_callback that became __return_true, a
capability check that disappeared.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyze import Finding, analyse_file, rank
from .diff import guard_set_regression
from .entrypoints import iter_php, scan_file
from .fetch import FetchError, info, plugin_root, recently_updated, release
from .index import build as build_index

DEFAULT_CACHE = Path.home() / ".cache" / "wp-authz-audit"

SEVERITY_COLOUR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}
RESET = "\033[0m"


def collect(root: Path, include_vendor: bool = False) -> tuple[list, list[Finding]]:
    # The index is built first so a capability check wrapped in a helper in
    # another file is still recognised as a guard.
    index = build_index(root, include_vendor)

    entries, findings = [], []
    for path in iter_php(root, include_vendor):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = scan_file(path, source)
        if not found:
            continue
        entries.extend(found)
        findings.extend(analyse_file(path, source, found, index))
    return entries, rank(findings)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def print_findings(findings: list[Finding], root: Path, colour: bool) -> None:
    if not findings:
        print("No authorization findings. This is not proof the plugin is safe — "
              "see the limits section in the README.")
        return

    for finding in findings:
        tint = SEVERITY_COLOUR.get(finding.severity, "") if colour else ""
        end = RESET if colour else ""
        print(
            f"{tint}{finding.severity.upper():<7}{end} {finding.cwe}  "
            f"[{finding.tier}]  {finding.title}"
        )
        print(f"        {_relative(finding.entry.file, root)}:{finding.entry.line}"
              f"  {finding.entry.kind} {finding.entry.hook} -> {finding.entry.callback}")
        for line in finding.evidence:
            print(f"          - {line}")
        print()

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(f"{count} {severity}" for severity, count in counts.items())
    print(f"{len(findings)} finding(s): {summary}")


def print_map(entries: list, root: Path) -> None:
    if not entries:
        print("No entry points found.")
        return
    for entry in sorted(entries, key=lambda e: (e.reach, str(e.file), e.line)):
        marker = "!" if entry.reach == 0 else " "
        permission = f"  perm={entry.permission_callback}" if entry.permission_callback else ""
        print(f"{marker} {entry.kind:<18} {entry.hook:<44} -> {entry.callback}{permission}")
        print(f"    {_relative(entry.file, root)}:{entry.line}")
    unauth = sum(1 for e in entries if e.reach == 0)
    print(f"\n{len(entries)} entry point(s); {unauth} reachable without authentication (marked !)")


def resolve_target(target: str, cache: Path) -> tuple[Path, str]:
    """A local path, or `slug` / `slug@version` fetched into the cache."""
    path = Path(target)
    if path.exists():
        return path, path.name

    slug, _, version = target.partition("@")
    meta = info(slug, cache)
    version = version or meta.version
    return plugin_root(release(slug, version, cache)), f"{slug}@{version}"


def command_audit(args: argparse.Namespace) -> int:
    root, label = resolve_target(args.target, args.cache)
    entries, findings = collect(root, args.include_vendor)

    if args.min_severity:
        order = ["high", "medium", "low", "info"]
        allowed = set(order[: order.index(args.min_severity) + 1])
        findings = [f for f in findings if f.severity in allowed]
    if args.unauth_only:
        findings = [f for f in findings if f.tier == "unauth"]

    if args.json:
        print(json.dumps(
            {"target": label, "entry_points": len(entries),
             "findings": [f.as_dict() for f in findings]},
            indent=2,
        ))
    else:
        print(f"# {label} — {len(entries)} entry points\n")
        print_findings(findings, root, args.colour)

    return 1 if any(f.severity == "high" for f in findings) else 0


def command_map(args: argparse.Namespace) -> int:
    root, label = resolve_target(args.target, args.cache)
    entries, _ = collect(root, args.include_vendor)
    if args.json:
        print(json.dumps(
            {"target": label,
             "entry_points": [
                 {"kind": e.kind, "hook": e.hook, "callback": e.callback,
                  "file": str(e.file), "line": e.line,
                  "permission_callback": e.permission_callback,
                  "reachable_unauthenticated": e.reach == 0}
                 for e in entries]},
            indent=2,
        ))
    else:
        print(f"# {label}\n")
        print_map(entries, root)
    return 0


def command_diff(args: argparse.Namespace) -> int:
    meta = info(args.slug, args.cache)
    new = args.new or meta.version
    old = args.old or meta.previous(new)
    if not old:
        print(f"no release older than {new} for {args.slug}", file=sys.stderr)
        return 2

    old_root = plugin_root(release(args.slug, old, args.cache))
    new_root = plugin_root(release(args.slug, new, args.cache))

    regressions = guard_set_regression(old_root, new_root)

    if args.json:
        print(json.dumps(
            {"slug": args.slug, "from": old, "to": new,
             "regressions": [r.as_dict() for r in regressions]},
            indent=2,
        ))
        return 1 if regressions else 0

    print(f"# {args.slug}: {old} -> {new}\n")
    if not regressions:
        print("No entry point added and no guard weakened between these releases.")
        return 0
    for item in regressions:
        print(f"{item.change:<22} {item.entry.kind} {item.entry.hook} -> {item.entry.callback}")
        print(f"    {_relative(item.entry.file, new_root)}:{item.entry.line}")
        for line in item.evidence:
            print(f"      - {line}")
        print()
    print(f"{len(regressions)} regression(s) to review")
    return 1


def command_watch(args: argparse.Namespace) -> int:
    """Audit the most recently updated plugins — the discovery worklist."""
    slugs = args.slugs or recently_updated(args.count, args.cache)
    ranked = []

    for slug in slugs:
        try:
            meta = info(slug, args.cache)
            if meta.active_installs < args.min_installs:
                continue
            root = plugin_root(release(slug, meta.version, args.cache))
            _, findings = collect(root)
        except FetchError as error:
            print(f"skip {slug}: {error}", file=sys.stderr)
            continue

        high = [f for f in findings if f.severity == "high"]
        unauth = [f for f in high if f.tier == "unauth"]
        if high:
            ranked.append((len(unauth), len(high), meta, findings))

    ranked.sort(key=lambda row: (row[0], row[1], row[2].active_installs), reverse=True)

    for unauth_count, high_count, meta, findings in ranked:
        print(f"{meta.slug}@{meta.version}  installs={meta.active_installs:,}  "
              f"high={high_count} unauth={unauth_count}")
        for finding in findings[:3]:
            if finding.severity == "high":
                print(f"    {finding.cwe} [{finding.tier}] {finding.title}")
                print(f"      {finding.entry.hook} -> {finding.entry.callback}")
        print()

    print(f"{len(ranked)} of {len(slugs)} plugin(s) have high-severity findings")
    return 0


def build_parser() -> argparse.ArgumentParser:
    # Shared options live on a parent parser so they work in either position:
    # `wp-authz-audit --json audit x` and `wp-authz-audit audit x --json` both
    # parse. Putting them only at the top level is a wart people trip over.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--cache", type=Path, default=DEFAULT_CACHE,
                        help=f"download cache (default: {DEFAULT_CACHE})")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    common.add_argument("--no-colour", "--no-color", dest="colour", action="store_false",
                        help="disable ANSI colour")
    common.add_argument("--include-vendor", action="store_true",
                        help="also scan vendor/ and node_modules/")

    parser = argparse.ArgumentParser(
        prog="wp-authz-audit",
        parents=[common],
        description="Rank WordPress plugin entry points by missing authorization.",
    )
    parser.add_argument("--version", action="version", version=__version__)

    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", parents=[common],
                           help="ranked findings for one plugin")
    audit.add_argument("target", help="local path, or slug, or slug@version")
    audit.add_argument("--min-severity", choices=["high", "medium", "low", "info"],
                       default="medium")
    audit.add_argument("--unauth-only", action="store_true",
                       help="only findings exploitable with no credentials")
    audit.set_defaults(func=command_audit)

    mapper = sub.add_parser("map", parents=[common],
                            help="list every entry point (triage view)")
    mapper.add_argument("target", help="local path, or slug, or slug@version")
    mapper.set_defaults(func=command_map)

    diff = sub.add_parser("diff", parents=[common],
                          help="guard-set regression between two releases")
    diff.add_argument("slug")
    diff.add_argument("--from", dest="old", help="older version (default: previous release)")
    diff.add_argument("--to", dest="new", help="newer version (default: latest)")
    diff.set_defaults(func=command_diff)

    watch = sub.add_parser("watch", parents=[common],
                           help="audit recently updated plugins, ranked")
    watch.add_argument("slugs", nargs="*", help="explicit slugs (default: recently updated)")
    watch.add_argument("--count", type=int, default=20)
    watch.add_argument("--min-installs", type=int, default=1000,
                       help="skip plugins below this install count")
    watch.set_defaults(func=command_watch)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not sys.stdout.isatty():
        args.colour = False
    try:
        return args.func(args)
    except FetchError as error:
        print(f"fetch failed: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
