"""Turn the entry-point map into a ranked worklist.

The ranking is the product. A plugin produces dozens of entry points and the
interesting ones are a handful, so anything that reports everything equally has
just moved the reading problem rather than solved it.

Two rules do most of the work, and both are places where the usual tools give
the wrong answer:

  * A nonce check is not authorization. A handler whose only guard is
    check_ajax_referer() is CSRF-protected and completely unauthorized, which
    reads as clean to PHPCS's NonceVerification sniff.
  * A primitive capability is not an ownership check. `current_user_can(
    'edit_posts')` guarding a write to a request-supplied post id is CWE-863,
    and it reads as clean to anything that only asks whether current_user_can
    appears.

Severity is deliberately conservative in one direction: findings that need an
editor or administrator to exploit are downranked to INFO, because the programs
this targets exclude them. Unauthenticated and subscriber-level are the whole
game.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .entrypoints import EntryPoint
from .index import ProjectIndex
from .guards import (
    PRIMITIVE_TO_META,
    Guard,
    Sink,
    classify,
    has_ownership_comparison,
    request_controlled,
    sinks,
)
from .php import blank_noncode, functions

TIERS = ("unauth", "subscriber", "contributor", "author", "editor", "admin")

# Capability -> the lowest role that holds it. Used to say who can actually
# reach a handler, which decides whether a program will pay for it.
CAPABILITY_TIER = {
    "read": "subscriber",
    "edit_posts": "contributor",
    "delete_posts": "contributor",
    "upload_files": "author",
    "publish_posts": "author",
    "edit_published_posts": "author",
    "edit_others_posts": "editor",
    "edit_pages": "editor",
    "moderate_comments": "editor",
    "manage_categories": "editor",
    "edit_theme_options": "admin",
    "manage_options": "admin",
    "install_plugins": "admin",
    "activate_plugins": "admin",
    "edit_users": "admin",
    "list_users": "admin",
    "promote_users": "admin",
    "super_admin": "admin",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Meta keys whose name suggests writing them has a security consequence.
HIGH_VALUE_META = re.compile(
    r"cap|role|admin|key|token|secret|passw|price|paid|licen[cs]e|access|owner|"
    r"user_id|email|status|approve|verif",
    re.I,
)


@dataclass
class Finding:
    severity: str
    cwe: str
    title: str
    tier: str
    entry: EntryPoint
    evidence: list[str] = field(default_factory=list)
    guards: list[Guard] = field(default_factory=list)
    sink: Sink | None = None

    @property
    def location(self) -> str:
        return f"{self.entry.file}:{self.entry.line}"

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "cwe": self.cwe,
            "title": self.title,
            "required_privilege": self.tier,
            "kind": self.entry.kind,
            "hook": self.entry.hook,
            "callback": self.entry.callback,
            "file": str(self.entry.file),
            "line": self.entry.line,
            "sink": self.sink.function if self.sink else None,
            "sink_line": self.sink.line if self.sink else None,
            "guards": [
                {"function": g.function, "capability": g.capability, "line": g.line}
                for g in self.guards
            ],
            "evidence": self.evidence,
        }


def _tier_for_capabilities(guards: list[Guard]) -> str | None:
    """Lowest role that satisfies every capability guard present."""
    caps = [g.capability for g in guards if g.is_capability and g.capability]
    if not caps:
        return None
    ranks = [TIERS.index(CAPABILITY_TIER.get(cap, "admin")) for cap in caps]
    return TIERS[max(ranks)]


_PERMISSIVE = ("__return_true", "'__return_true'", '"__return_true"')


def _permission_callback_state(entry: EntryPoint) -> tuple[str, str]:
    """(state, human explanation) for a REST route's permission_callback."""
    raw = (entry.permission_callback or "").strip()
    if not raw:
        return "missing", (
            "permission_callback is absent; since WP 5.5 core only emits "
            "_doing_it_wrong and still serves the route publicly"
        )
    if raw.strip("'\"") == "__return_true":
        return "permissive", "permission_callback is __return_true"
    if "is_user_logged_in" in raw and "current_user_can" not in raw:
        return "login_only", "permission_callback only proves a session exists"
    if "current_user_can" in raw or "user_can" in raw:
        return "capability", "permission_callback performs a capability check"
    return "custom", f"custom permission_callback: {raw[:60]}"


def _body_for(entry: EntryPoint, source: str) -> tuple[str, int]:
    if entry.resolved:
        return entry.resolved.body(source), entry.resolved.line
    return "", entry.line


def analyse_file(
    path: Path,
    source: str,
    entries: list[EntryPoint],
    index: "ProjectIndex | None" = None,
) -> list[Finding]:
    findings: list[Finding] = []
    blanked = blank_noncode(source)
    defined = {f.name: f for f in functions(source, blanked)}

    for entry in entries:
        body, body_line = _body_for(entry, source)

        # A handler that delegates its checks to a helper inherits that helper's
        # guards. Same-file helpers are always followed; with a project index,
        # guard-like helpers in OTHER files are followed too. Real plugins wrap
        # current_user_can() in their own function far more often than not, and
        # without cross-file resolution correct code reads as critical.
        helper_bodies = _helper_guard_bodies(entry, defined, blanked, source)
        combined = body + "\n" + "\n".join(helper_bodies)
        if index is not None:
            combined = index.inline_guards(combined)
        guards, pseudo_notes = classify(combined, body_line)
        found_sinks = sinks(body, body_line) if body else []
        reads_request = request_controlled(body) if body else False

        findings.extend(
            _judge(entry, guards, pseudo_notes, found_sinks, reads_request, body)
        )

    return findings


def _helper_guard_bodies(entry, defined, blanked, source) -> list[str]:
    """Bodies of same-file helpers the handler calls, for guard inheritance."""
    if not entry.resolved:
        return []

    handler_body = blanked[entry.resolved.body_start : entry.resolved.body_end]
    bodies = []
    for name, function in defined.items():
        if name == entry.resolved.name:
            continue
        # '>' and ':' must be allowed before the name: the common shape is
        # `$this->may_export()`, and excluding them was silently disabling
        # guard inheritance for every method-based helper.
        if re.search(rf"(?<![\w$]){re.escape(name)}\s*\(", handler_body):
            bodies.append(function.body(source))
    return bodies


def _judge(
    entry: EntryPoint,
    guards: list[Guard],
    pseudo_notes: list[str],
    found_sinks: list[Sink],
    reads_request: bool,
    body: str,
) -> list[Finding]:
    capability_guards = [g for g in guards if g.is_capability]
    nonce_guards = [g for g in guards if g.is_nonce]
    writes = [s for s in found_sinks if s.kind in ("object_write", "global_write")]
    tainted_writes = [s for s in found_sinks if s.kind == "object_write" and s.tainted_object_id]

    tier = _tier_for_capabilities(capability_guards)
    findings: list[Finding] = []

    def add(severity, cwe, title, evidence, sink=None, at_tier=None):
        findings.append(
            Finding(
                severity=severity,
                cwe=cwe,
                title=title,
                tier=at_tier or tier or ("unauth" if entry.reach == 0 else "subscriber"),
                entry=entry,
                evidence=evidence + pseudo_notes,
                guards=guards,
                sink=sink,
            )
        )

    # --- REST routes -----------------------------------------------------
    if entry.kind == "rest":
        state, explanation = _permission_callback_state(entry)

        if state == "missing" and writes:
            add("high", "CWE-862", "REST route with no permission_callback performs writes",
                [explanation, f"state-changing call: {writes[0].function}()"], writes[0], "unauth")
        elif state == "missing":
            add("medium", "CWE-862", "REST route registered without permission_callback",
                [explanation], None, "unauth")
        elif state == "permissive" and writes:
            add("high", "CWE-862", "Public REST route performs a state-changing operation",
                [explanation, f"state-changing call: {writes[0].function}()"], writes[0], "unauth")
        elif state == "login_only" and writes:
            add("medium", "CWE-862",
                "REST route guarded only by is_user_logged_in performs writes",
                [explanation, f"state-changing call: {writes[0].function}()"],
                writes[0], "subscriber")
        elif state == "permissive" and not writes:
            # The single biggest false-positive source in every other tool.
            # A public read route is a legitimate design, so this is not a finding.
            pass

        if state == "capability" and tainted_writes:
            primitive = next(
                (g.capability for g in capability_guards
                 if g.capability in PRIMITIVE_TO_META and not g.has_object_argument),
                None,
            )
            if primitive and not has_ownership_comparison(body):
                add("high", "CWE-863",
                    "REST permission_callback checks a primitive capability while the "
                    "handler writes to a request-supplied object",
                    [f"guard is current_user_can('{primitive}') with no object argument",
                     f"map_meta_cap enforces ownership only via '{PRIMITIVE_TO_META[primitive]}' "
                     f"with the object id as second argument",
                     f"write: {tainted_writes[0].function}() on a request-controlled id"],
                    tainted_writes[0])

    # --- AJAX / admin-post / lifecycle -----------------------------------
    elif entry.kind in ("ajax_nopriv", "admin_post_nopriv"):
        if writes:
            add("high", "CWE-862",
                "Unauthenticated handler performs a state-changing operation",
                [f"{entry.hook} is reachable with no credentials",
                 f"state-changing call: {writes[0].function}()",
                 "a nonce here is CSRF defence, not authorization" if nonce_guards else
                 "no guard of any kind in the handler"],
                writes[0], "unauth")
        elif reads_request:
            add("medium", "CWE-862", "Unauthenticated handler reads request data",
                [f"{entry.hook} is reachable with no credentials"], None, "unauth")

    elif entry.kind in ("ajax", "admin_post"):
        if not capability_guards and writes:
            add("high", "CWE-862",
                "Handler reachable by any logged-in user performs a state-changing "
                "operation with no capability check",
                [f"{entry.hook} is reachable by any authenticated user, including subscribers",
                 f"state-changing call: {writes[0].function}()",
                 "only a nonce check is present — that is CSRF defence, not authorization"
                 if nonce_guards else "no capability check in the handler"],
                writes[0], "subscriber")
        elif capability_guards and tainted_writes:
            primitive = next(
                (g.capability for g in capability_guards
                 if g.capability in PRIMITIVE_TO_META and not g.has_object_argument),
                None,
            )
            if primitive and not has_ownership_comparison(body):
                add("high", "CWE-863",
                    "Primitive capability check guards a write to a request-supplied object",
                    [f"guard is current_user_can('{primitive}') with no object argument",
                     f"ownership is enforced only by '{PRIMITIVE_TO_META[primitive]}' with the "
                     f"object id as second argument",
                     f"write: {tainted_writes[0].function}() on a request-controlled id"],
                    tainted_writes[0])

    elif entry.kind == "lifecycle":
        if reads_request and writes and not capability_guards:
            add("high", "CWE-862",
                f"{entry.hook} handler acts on request data with no capability check",
                [f"{entry.hook} runs before any authentication branch",
                 f"state-changing call: {writes[0].function}()"],
                writes[0], "unauth")
        elif reads_request and not capability_guards:
            add("low", "CWE-862", f"{entry.hook} handler reads request data unguarded",
                [f"{entry.hook} runs before any authentication branch"], None, "unauth")

    elif entry.kind == "meta":
        raw = (entry.permission_callback or "").strip("'\" ")
        if raw == "__return_true":
            key = entry.hook.rsplit(":", 1)[-1]
            # The pattern is identical whether the key is a licence token or a
            # boolean "content changed" flag, but the consequence is not. The
            # name is the only signal available statically, so it sets severity
            # rather than deciding whether to report at all.
            sensitive = bool(HIGH_VALUE_META.search(key))
            evidence = [
                "auth_callback is __return_true, so any user who can reach the object's "
                "REST endpoint can write this meta key",
                "core's default auth_callback would have required a capability",
            ]
            if not sensitive:
                evidence.append(
                    f"'{key}' does not look security-relevant — confirm what writing it "
                    "actually changes before treating this as a finding"
                )
            add("high" if sensitive else "medium", "CWE-862",
                "REST-exposed meta key with a permissive auth_callback",
                evidence, None, "subscriber")

    return findings


def rank(findings: list[Finding]) -> list[Finding]:
    """Most-exploitable first: severity, then attacker privilege required."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            TIERS.index(f.tier) if f.tier in TIERS else 9,
            str(f.entry.file),
            f.entry.line,
        ),
    )
