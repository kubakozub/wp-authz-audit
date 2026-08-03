"""Project-wide function index, so a guard in another file still counts.

This exists because of a false positive found by running the tool against a real
plugin. Advanced Custom Fields guards its AJAX handlers with

    if ( ! acf_verify_ajax() || ! acf_current_user_can_admin() ) { ... }

`acf_current_user_can_admin()` is a one-line wrapper around `current_user_can()`
defined in a different file. A same-file-only analyser sees a handler with no
recognised guard and reports a critical finding on correctly written code.

Wrapping a capability check in a helper is normal, good practice in any plugin
large enough to be worth auditing, so an analyser that cannot follow one is not
usable on real code. The index resolves calls across the whole tree and inlines
the bodies of guard-like helpers up to a small depth.

Depth is capped at 2 deliberately. Deeper chains exist, but each level makes the
"this handler is guarded" claim weaker, and an unbounded walk on a large plugin
turns a four-second scan into a minute. The cap is a limit, and it is documented
as one rather than hidden.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .guards import CAPABILITY_FUNCTIONS
from .php import Function, blank_noncode, functions

MAX_DEPTH = 2

# A helper only counts as a guard source if it plausibly performs a check.
# Requiring a capability call in the body keeps ordinary helpers out.
_GUARDISH = re.compile(
    r"|".join(re.escape(name) for name in sorted(CAPABILITY_FUNCTIONS)), re.I
)


@dataclass
class ProjectIndex:
    """Every named function in the tree, by bare name."""

    bodies: dict[str, str] = field(default_factory=dict)
    guard_names: set[str] = field(default_factory=set)

    def add_file(self, source: str, blanked: str | None = None) -> None:
        blanked = blank_noncode(source) if blanked is None else blanked
        for function in functions(source, blanked):
            body = function.body(source)
            # First definition wins; plugins redefine names across builds and
            # the first is the one the autoloader usually reaches.
            self.bodies.setdefault(function.name, body)
            if _GUARDISH.search(blank_noncode(body)):
                self.guard_names.add(function.name)

    def called_names(self, body: str) -> set[str]:
        """Names called in a body that this index knows about."""
        blanked = blank_noncode(body)
        found = set()
        for name in self.guard_names:
            if re.search(rf"(?<![\w$]){re.escape(name)}\s*\(", blanked):
                found.add(name)
        return found

    def inline_guards(self, body: str, depth: int = MAX_DEPTH) -> str:
        """Body plus the bodies of guard-like helpers it reaches.

        Only guard-like helpers are inlined. Pulling in every callee would make
        unrelated capability checks elsewhere in the plugin look like they
        protect this handler, which trades false positives for false negatives —
        the worse direction for an audit tool.
        """
        if depth <= 0 or not body:
            return body

        parts = [body]
        seen: set[str] = set()
        frontier = self.called_names(body)

        for _ in range(depth):
            if not frontier:
                break
            following: set[str] = set()
            for name in sorted(frontier - seen):
                seen.add(name)
                helper = self.bodies.get(name)
                if not helper:
                    continue
                parts.append(helper)
                following |= self.called_names(helper)
            frontier = following - seen

        return "\n".join(parts)


def build(root: Path, include_vendor: bool = False) -> ProjectIndex:
    from .entrypoints import iter_php

    index = ProjectIndex()
    for path in iter_php(root, include_vendor):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        index.add_file(source)
    return index
