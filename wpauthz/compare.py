"""Compare two plugins that share ancestry, and report where their guards differ.

`diff` compares one plugin across releases. This compares two plugins against
each other, which turns out to be a different and often better instrument.

Vendors ship families: a free and a pro edition, a fork, or four products built
on one shared framework. The same function appears in all of them, usually with
the same name, because it started as the same code. When one sibling checks
something the others do not, that asymmetry is worth more than any absolute
judgement about a single plugin — the siblings act as each other's specification.

The strongest signal is a guard present in the majority and absent in one:

    3 of 4 siblings:  if ( empty( $token ) ) { fail(); }
    the fourth:       (missing)

That is not proof of a vulnerability. A real session produced exactly this shape
across four plugins from one vendor, and reading the code showed the missing
check was defence in depth rather than an exploitable gap. The value is that it
took ten seconds to find and five minutes to settle, instead of reading four
plugins end to end.

Functions are matched on their QUALIFIED name (Class::method), plus bare names
that are unambiguous within every tree — a rebranded fork keeps its method names
but not its class names. Matching on bare names alone and keeping the longest
body made results depend on tree SIZE: the larger sibling was likelier to hold
an unrelated class with a same-named longer method, which won the slot and got
compared against the wrong code, so byte-identical functions read as divergent.
A comparison that is not deterministic is worse than none, because every result
then needs checking against the possibility that it is an artefact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .entrypoints import iter_php
from .guards import CAPABILITY_FUNCTIONS, NONCE_FUNCTIONS, classify
from .php import blank_noncode, functions

# Checks whose absence in one sibling is worth surfacing, beyond the guard
# functions themselves. These are the shapes that fail closed.
_EARLY_EXIT_MARKERS = (
    "empty(",
    "isset(",
    "is_null(",
    "!==",
    "hash_equals(",
    "wp_die(",
    "wp_send_json_error(",
)


@dataclass
class FunctionFacts:
    """What a function checks, reduced to something comparable."""

    plugin: str
    file: Path
    line: int
    capabilities: frozenset[str]
    nonce_actions: frozenset[str]
    guard_functions: frozenset[str]
    early_exits: int
    length: int


@dataclass
class Divergence:
    name: str
    present_in: list[str]
    missing_in: list[str]
    detail: str
    facts: dict[str, FunctionFacts] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "function": self.name,
            "guard_present_in": self.present_in,
            "guard_missing_in": self.missing_in,
            "detail": self.detail,
            "locations": {
                plugin: f"{fact.file}:{fact.line}"
                for plugin, fact in self.facts.items()
            },
        }


def _facts(root: Path, label: str) -> dict[str, FunctionFacts]:
    collected: dict[str, FunctionFacts] = {}

    for path in iter_php(root):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        blanked = blank_noncode(source)

        for function in functions(source, blanked):
            body = function.body(source)
            guards, _ = classify(body)
            blanked_body = blank_noncode(body)

            fact = FunctionFacts(
                plugin=label,
                file=path.relative_to(root) if path.is_relative_to(root) else path,
                line=function.line,
                capabilities=frozenset(
                    g.capability for g in guards if g.is_capability and g.capability
                ),
                nonce_actions=frozenset(
                    g.capability for g in guards if g.is_nonce and g.capability
                ),
                guard_functions=frozenset(
                    g.function
                    for g in guards
                    if g.function in (CAPABILITY_FUNCTIONS | NONCE_FUNCTIONS)
                ),
                early_exits=sum(blanked_body.count(m) for m in _EARLY_EXIT_MARKERS),
                length=len(body),
            )
            # Key by QUALIFIED name. Keying by bare name and keeping the
            # longest definition made the comparison non-deterministic: a
            # larger sibling is likelier to contain some other class with a
            # same-named, longer method, so that unrelated body won the slot
            # and the two trees were no longer compared like for like. That
            # produced a divergence on code that was byte-identical, which
            # undermines the whole premise of comparing siblings.
            key = function.qualified
            existing = collected.get(key)
            if existing is None or fact.length > existing.length:
                collected[key] = fact

    return collected


def _merge_keys(facts: dict[str, FunctionFacts]) -> dict[str, FunctionFacts]:
    """Add bare-name keys for methods whose bare name is unique in this tree."""
    bare_counts: dict[str, int] = {}
    for qualified in facts:
        bare = qualified.rsplit("::", 1)[-1]
        bare_counts[bare] = bare_counts.get(bare, 0) + 1

    merged = dict(facts)
    for qualified, fact in facts.items():
        bare = qualified.rsplit("::", 1)[-1]
        if bare_counts[bare] == 1 and f"~{bare}" not in merged:
            # Prefixed so a bare key can never collide with a qualified one.
            merged[f"~{bare}"] = fact
    return merged


def compare(trees: list[tuple[str, Path]], min_shared: int = 2) -> list[Divergence]:
    """Functions defined in several trees where one is guarded differently.

    `min_shared` is how many trees must define a name before a difference is
    interesting. With two trees any difference qualifies; with four, requiring
    three shared definitions turns the majority into a specification.
    """
    per_plugin = {label: _facts(root, label) for label, root in trees}

    # Qualified names match a fork that kept its class names. A fork that
    # renamed them (a rebrand) still shares method names, so unambiguous bare
    # names are matched too — "unambiguous" meaning exactly one definition of
    # that bare name in every tree. Ambiguity was the actual bug: with several
    # candidates the largest body won, and that depended on tree size.
    per_plugin = {
        label: _merge_keys(facts) for label, facts in per_plugin.items()
    }

    names: dict[str, list[str]] = {}
    for label, facts in per_plugin.items():
        for name in facts:
            names.setdefault(name, []).append(label)

    divergences: list[Divergence] = []

    for name, labels in sorted(names.items()):
        if len(labels) < min_shared:
            continue
        facts = {label: per_plugin[label][name] for label in labels}

        for attribute, description in (
            ("guard_functions", "guard call"),
            ("capabilities", "capability check"),
        ):
            union: set[str] = set()
            for fact in facts.values():
                union |= getattr(fact, attribute)
            if not union:
                continue

            for item in sorted(union):
                present = [l for l in labels if item in getattr(facts[l], attribute)]
                missing = [l for l in labels if item not in getattr(facts[l], attribute)]
                # With three or more siblings, only a MAJORITY-present check is
                # a specification: a check in one of four is more likely a local
                # feature than a gap in the other three. With exactly two there
                # is no majority, and the comparison was asked for explicitly,
                # so any difference is reported.
                majority = len(present) > len(missing) or len(labels) == 2
                if missing and majority:
                    divergences.append(
                        Divergence(
                            name=name,
                            present_in=present,
                            missing_in=missing,
                            detail=f"{description} {item}() present in "
                            f"{len(present)}/{len(labels)} siblings",
                            facts=facts,
                        )
                    )

        # An early-exit gap: same function, materially fewer fail-closed checks.
        counts = {label: facts[label].early_exits for label in labels}
        highest = max(counts.values())
        lowest = min(counts.values())
        if highest - lowest >= 2 and highest >= 2:
            weakest = [l for l in labels if counts[l] == lowest]
            strongest = [l for l in labels if counts[l] > lowest]
            if len(strongest) > len(weakest):
                divergences.append(
                    Divergence(
                        name=name,
                        present_in=strongest,
                        missing_in=weakest,
                        detail=f"{highest} fail-closed checks in the majority, "
                        f"{lowest} in {', '.join(weakest)}",
                        facts=facts,
                    )
                )

    # Guard-call gaps first: they name a specific missing check, which is what a
    # reviewer can act on. Early-exit counts are a weaker, shape-level hint.
    # A function is matched twice on purpose — once by qualified name, once by
    # unambiguous bare name — so the same divergence arrives twice. Collapse on
    # what a reader actually sees.
    deduped: dict[tuple[str, str], Divergence] = {}
    for divergence in divergences:
        divergence.name = divergence.name.lstrip("~")
        deduped.setdefault((divergence.name, divergence.detail), divergence)
    divergences = list(deduped.values())

    return sorted(
        divergences,
        key=lambda d: (0 if "present in" in d.detail else 1, -len(d.present_in), d.name),
    )
