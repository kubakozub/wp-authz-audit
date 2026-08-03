"""Guard-set regression: what got weaker between two releases.

Reviewing changed lines is the obvious approach and it is the wrong one. A
release diff is mostly refactors, translations and asset churn, so line-level
review puts you back where you started — reading a lot to find a little.

Comparing the entry-point GRAPH answers a narrower and far more useful question:
did anything become reachable that was not, or did a guard get weaker? Four
regressions are worth a human's attention:

  new_entry_point      a hook that did not exist in the old release
  permission_weakened  a REST permission_callback moved toward permissive
  guard_removed        a capability check present in the old handler is gone
  sink_added           a new state-changing call inside an already-unguarded handler

Everything else — new code that is guarded the same way as before, cosmetic
churn, moved files — is silence. That silence is the point.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .analyze import _permission_callback_state
from .entrypoints import EntryPoint, iter_php, scan_file
from .guards import classify, sinks
from .index import build as build_index

PERMISSION_RANK = {
    "capability": 0,
    "custom": 1,
    "login_only": 2,
    "permissive": 3,
    "missing": 4,
}


@dataclass
class Regression:
    change: str
    entry: EntryPoint
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "change": self.change,
            "kind": self.entry.kind,
            "hook": self.entry.hook,
            "callback": self.entry.callback,
            "file": str(self.entry.file),
            "line": self.entry.line,
            "evidence": self.evidence,
        }


@dataclass
class Snapshot:
    entry: EntryPoint
    capabilities: frozenset[str]
    sink_names: frozenset[str]
    permission_state: str


def _snapshot(root: Path) -> dict[tuple[str, str], Snapshot]:
    """Entry points keyed by (kind, hook), with their guards and sinks."""
    taken: dict[tuple[str, str], Snapshot] = {}
    index = build_index(root)

    for path in iter_php(root):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for entry in scan_file(path, source):
            body = entry.resolved.body(source) if entry.resolved else ""
            # Same cross-file guard resolution as the audit path, otherwise a
            # release that merely moved a check into a helper reads as a
            # removed guard.
            guards, _ = classify(index.inline_guards(body) if body else "")
            capabilities = frozenset(
                guard.capability
                for guard in guards
                if guard.is_capability and guard.capability
            )
            names = frozenset(sink.function for sink in sinks(body)) if body else frozenset()
            state, _ = _permission_callback_state(entry)

            key = (entry.kind, entry.hook)
            # A hook registered twice: keep the weaker guard set, which is what
            # an attacker gets to use.
            existing = taken.get(key)
            if existing and len(existing.capabilities) <= len(capabilities):
                continue
            taken[key] = Snapshot(entry, capabilities, names, state)

    return taken


def guard_set_regression(old_root: Path, new_root: Path) -> list[Regression]:
    old = _snapshot(old_root)
    new = _snapshot(new_root)
    regressions: list[Regression] = []

    for key, current in new.items():
        kind, hook = key
        previous = old.get(key)

        if previous is None:
            evidence = [f"{hook} does not exist in the older release"]
            # permission_callback is a REST concept; reporting its "state" for
            # an AJAX hook is noise that reads like a finding.
            if kind == "rest" and current.permission_state in ("missing", "permissive"):
                evidence.append(f"permission_callback state: {current.permission_state}")
            if current.entry.reach == 0:
                evidence.append("reachable without authentication")
            if current.sink_names:
                evidence.append(
                    "state-changing calls: " + ", ".join(sorted(current.sink_names)[:4])
                )
            if current.entry.reach == 0 or current.sink_names:
                regressions.append(Regression("new_entry_point", current.entry, evidence))
            continue

        if kind == "rest" and PERMISSION_RANK.get(
            current.permission_state, 1
        ) > PERMISSION_RANK.get(previous.permission_state, 1):
            regressions.append(
                Regression(
                    "permission_weakened",
                    current.entry,
                    [f"permission_callback went from {previous.permission_state} "
                     f"to {current.permission_state}"],
                )
            )

        dropped = previous.capabilities - current.capabilities
        if dropped:
            regressions.append(
                Regression(
                    "guard_removed",
                    current.entry,
                    [f"capability check(s) no longer present: {', '.join(sorted(dropped))}"],
                )
            )

        added_sinks = current.sink_names - previous.sink_names
        if added_sinks and not current.capabilities:
            regressions.append(
                Regression(
                    "sink_added",
                    current.entry,
                    [f"new state-changing call(s) in an unguarded handler: "
                     f"{', '.join(sorted(added_sinks)[:4])}"],
                )
            )

    order = {"permission_weakened": 0, "guard_removed": 1, "new_entry_point": 2, "sink_added": 3}
    return sorted(
        regressions,
        key=lambda r: (order.get(r.change, 9), r.entry.reach, str(r.entry.file)),
    )
