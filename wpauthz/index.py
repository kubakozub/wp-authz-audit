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

Depth is capped deliberately. Deeper chains exist, but each level makes the
"this handler is guarded" claim weaker, and an unbounded walk on a large plugin
turns a four-second scan into a minute. The cap is a limit, and it is documented
as one rather than hidden.

The index is keyed by BARE function name and keeps every definition of each
name. Keying by bare name is imprecise — two classes may both define
`get_results()` — but keeping only the first silently resolved a delegation to
the wrong method, which hid a handler that returns the site's user list. Keeping
all of them over-approximates instead, which is the safe direction here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .guards import CAPABILITY_FUNCTIONS, NONCE_FUNCTIONS
from .php import (
    Function,
    blank_noncode,
    calls,
    classes,
    functions,
    literal,
    property_literals,
)

MAX_DEPTH = 3

_CALL_NAME = re.compile(r"(?<![\w$])([A-Za-z_]\w*)\s*\(")
_NONCE_MINT = re.compile(r"wp_create_nonce\s*\(\s*['\"]([^'\"]+)['\"]")

# A helper only counts as a guard source if it plausibly performs a check.
# Nonce functions are included even though a nonce is NOT authorization: if a
# delegate does the nonce check, the analyser must see it, otherwise the finding
# says "no guard at all" when the truth is "only CSRF defence" — a different and
# less alarming claim, and the difference is the whole point of the tool.
_GUARDISH = re.compile(
    r"|".join(
        re.escape(name) for name in sorted(CAPABILITY_FUNCTIONS | NONCE_FUNCTIONS)
    ),
    re.I,
)


@dataclass
class ProjectIndex:
    """Every named function in the tree, by bare name, plus property literals."""

    # ALL definitions per bare name, not just the first. A plugin routinely has
    # several methods called get_results() on different classes; keeping only
    # the first silently resolves a delegation to the wrong one, which is how a
    # handler that returns the site's user list looked like it returned nothing.
    bodies: dict[str, list[str]] = field(default_factory=dict)
    guard_names: set[str] = field(default_factory=set)
    properties: dict[str, set[str]] = field(default_factory=dict)
    option_writes: dict[str, set[str]] = field(default_factory=dict)
    # Filled in after the entry-point map exists; see cli.collect().
    public_nonces: set[str] = field(default_factory=set)
    # Class name -> ClassInfo, for resolving properties through `extends`.
    class_table: dict = field(default_factory=dict)

    def resolve_string(self, class_name: str, prop: str) -> str | None:
        """Property value for a class, walking up the inheritance chain."""
        seen: set[str] = set()
        current = class_name
        while current and current not in seen:
            seen.add(current)
            info = self.class_table.get(current)
            if info is None:
                return None
            if prop in info.strings:
                return info.strings[prop]
            current = info.parent
        return None

    def resolve_bool(self, class_name: str, prop: str) -> bool | None:
        seen: set[str] = set()
        current = class_name
        while current and current not in seen:
            seen.add(current)
            info = self.class_table.get(current)
            if info is None:
                return None
            if prop in info.booleans:
                return info.booleans[prop]
            current = info.parent
        return None

    def descendants(self, class_name: str) -> list[str]:
        """Every class that inherits from `class_name`, plus itself."""
        out = [class_name]
        frontier = {class_name}
        while frontier:
            children = {
                name
                for name, info in self.class_table.items()
                if info.parent in frontier and name not in out
            }
            if not children:
                break
            out.extend(sorted(children))
            frontier = children
        return out

    def ancestry_bodies(self, class_name: str) -> list[str]:
        """Method bodies of a class and everything it inherits from."""
        bodies: list[str] = []
        seen: set[str] = set()
        current = class_name
        while current and current not in seen:
            seen.add(current)
            info = self.class_table.get(current)
            if info is None:
                break
            bodies.extend(info.methods.values())
            current = info.parent
        return bodies

    def add_file(self, source: str, blanked: str | None = None) -> None:
        blanked = blank_noncode(source) if blanked is None else blanked
        for function in functions(source, blanked):
            body = function.body(source)
            self.bodies.setdefault(function.name, []).append(body)
            if _GUARDISH.search(blank_noncode(body)):
                self.guard_names.add(function.name)

        for info in classes(source, blanked):
            self.class_table.setdefault(info.name, info)

        for name, values in property_literals(source, blanked).items():
            self.properties.setdefault(name, set()).update(values)

        self._record_option_writes(source, blanked)

    def _record_option_writes(self, source: str, blanked: str) -> None:
        """Every literal value each option name is ever written with.

        Used to tell a settings write from a one-shot flag. An option only ever
        set to true/false carries no data an attacker wants; reporting a write
        to it at the same severity as a licence key is how a tool earns a
        reputation for crying wolf.
        """
        for name in ("update_option", "add_option", "delete_option"):
            for call in calls(name, source, blanked):
                if not call.args:
                    continue
                option = literal(call.args[0])
                if not option:
                    continue
                value = call.args[1].strip() if len(call.args) > 1 else ""
                self.option_writes.setdefault(option, set()).add(value)

    def nonce_audience(self, action: str) -> str | None:
        """Lowest role that is ever handed a nonce for `action`, if gated.

        A nonce-only handler normally reads as reachable by any logged-in user.
        That is wrong when the nonce is only ever minted inside a branch gated
        on a role or capability: a subscriber is never issued one and cannot
        forge one for their own session, so the real bar is that gate.

        Returns None when at least one emission site is ungated, or when no
        emission site is found at all — the safe answer in both cases is "do
        not raise the bar".
        """
        pattern = re.compile(
            rf"wp_create_nonce\s*\(\s*['\"]{re.escape(action)}['\"]"
        )
        emitting = [
            body
            for bodies in self.bodies.values()
            for body in bodies
            if pattern.search(body)
        ]
        if not emitting:
            return None

        gates: set[str] = set()
        for body in emitting:
            gate = _emission_gate(body)
            if gate is None:
                return None  # one ungated emitter is enough to hand nonces out
            gates.add(gate)
        return "admin" if "administrator" in gates or "admin" in gates else None

    def public_nonce_actions(self, unauth_bodies: list[str]) -> set[str]:
        """Nonce actions any anonymous caller can obtain.

        The mirror image of `nonce_audience`. If a nopriv endpoint hands out
        `wp_create_nonce('x')`, then every handler guarded only by a nonce for
        'x' is effectively unauthenticated: the attacker fetches a token from
        the public endpoint and replays it. Plugins ship these token vendors
        deliberately — public forms need them — which is what makes the pattern
        both common and easy to miss.
        """
        actions: set[str] = set()
        for body in unauth_bodies:
            expanded = self.inline_callees(body, depth=2)
            for match in _NONCE_MINT.finditer(expanded):
                actions.add(match.group(1))
        return actions

    def option_is_flag_only(self, option: str) -> bool:
        """True when every recorded write to this option is a boolean literal."""
        values = self.option_writes.get(option)
        if not values:
            return False
        meaningful = {v for v in values if v}
        if not meaningful:
            return False
        return all(v.lower() in ("true", "false", "1", "0", "'1'", '"1"') for v in meaningful)

    def called_names(self, body: str, guards_only: bool = True) -> set[str]:
        """Names called in a body that this index knows about.

        Extracts identifiers from the body once and intersects with the index,
        rather than searching for every known name in turn — the latter is
        O(functions x handlers) and gets slow on a large plugin.
        """
        blanked = blank_noncode(body)
        called = {match.group(1) for match in _CALL_NAME.finditer(blanked)}
        pool = self.guard_names if guards_only else self.bodies.keys()
        return called & set(pool)

    def inline_callees(self, body: str, depth: int = 2) -> str:
        """Body plus the bodies of everything it calls, for sink detection.

        Guard inlining is deliberately narrow — only guard-like helpers — so
        that an unrelated capability check elsewhere cannot make a handler look
        protected. Sink detection needs the opposite bias: a handler that
        delegates its actual work to `$this->get_results()` still performs
        whatever that method performs, and missing it is a false negative.

        The index is keyed by bare function name, so an unrelated class with a
        same-named method can be pulled in. That over-approximates reachable
        sinks, which is the safer direction here, and findings say which helper
        contributed.
        """
        if depth <= 0 or not body:
            return body

        parts = [body]
        seen: set[str] = set()
        frontier = self.called_names(body, guards_only=False)

        for _ in range(depth):
            if not frontier:
                break
            following: set[str] = set()
            for name in sorted(frontier - seen):
                seen.add(name)
                for helper in self.bodies.get(name, ()):
                    parts.append(helper)
                    following |= self.called_names(helper, guards_only=False)
            frontier = following - seen

        return "\n".join(parts)

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
                for helper in self.bodies.get(name, ()):
                    parts.append(helper)
                    following |= self.called_names(helper)
            frontier = following - seen

        return "\n".join(parts)


_ROLE_GATE = re.compile(
    r"array_intersect\s*\(\s*[^)]*?['\"](administrator|editor|author|contributor)['\"]"
    r"|current_user_can\s*\(\s*['\"](manage_options|activate_plugins|edit_theme_options)['\"]"
    r"|is_super_admin\s*\(",
    re.I,
)


def _emission_gate(body: str) -> str | None:
    """The role a nonce emitter is gated behind, or None if it is ungated."""
    match = _ROLE_GATE.search(blank_noncode(body))
    if not match:
        return None
    return (match.group(1) or "administrator").lower()


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
