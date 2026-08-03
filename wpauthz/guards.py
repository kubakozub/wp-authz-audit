"""What counts as an authorization check in WordPress, and what only looks like one.

Most scanners get this wrong in the same way: they see any of `wp_verify_nonce`,
`check_ajax_referer`, `is_admin` or `is_user_logged_in` near a handler and mark
it protected. Each of those answers a different question:

  * A nonce proves the request was INTENDED by the user who sent it. That is
    CSRF defence. A subscriber can legitimately obtain nonces — plugins hand
    them to the browser through wp_localize_script — so a nonce never
    establishes that the caller is ALLOWED to perform the action.
  * `is_admin()` is true for any request to /wp-admin/admin-ajax.php, including
    an unauthenticated one. It means "this is an admin-area request", never
    "this user is an administrator".
  * `is_user_logged_in()` separates anonymous from authenticated. On a site
    with open registration or WooCommerce customers, that is not a privilege
    boundary.

Only the capability family actually answers "may this user do this".

The second distinction, which is where the interesting bugs live: WordPress
splits PRIMITIVE capabilities from META capabilities. `current_user_can(
'edit_posts')` asks whether the user may edit posts in general — every
Contributor may. `current_user_can('edit_post', $id)` runs map_meta_cap()
against that specific object and is what actually enforces ownership. A handler
that takes an object id from the request, checks only the primitive capability,
and then writes to that object is CWE-863, and it passes every tool that merely
looks for the presence of `current_user_can`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Real authorization: these resolve a capability for a user.
CAPABILITY_FUNCTIONS = frozenset(
    {
        "current_user_can",
        "current_user_can_for_blog",
        "current_user_can_for_site",
        "user_can",
        "author_can",
        "is_super_admin",
        "is_user_member_of_blog",
    }
)

# CSRF defence only. Necessary, never sufficient.
NONCE_FUNCTIONS = frozenset(
    {
        "wp_verify_nonce",
        "check_admin_referer",
        "check_ajax_referer",
        "wp_check_password",
    }
)

# Which argument carries the nonce ACTION, per function.
NONCE_ACTION_POSITION = {
    "wp_verify_nonce": 1,
    "check_admin_referer": 0,
    "check_ajax_referer": 0,
}

# Frequently mistaken for authorization.
PSEUDO_GUARDS = {
    "is_admin": (
        "is_admin() is true for any request to admin-ajax.php, including "
        "unauthenticated ones — it is not a privilege check"
    ),
    "is_user_logged_in": (
        "is_user_logged_in() separates anonymous from authenticated; on a site "
        "with open registration that is not a privilege boundary"
    ),
    "is_admin_bar_showing": "cosmetic, unrelated to authorization",
    "wp_get_current_user": (
        "retrieving the current user is not a check unless the result is "
        "compared against the object being acted on"
    ),
}

# Capabilities so widely held that requiring them is close to requiring nothing.
WEAK_CAPABILITIES = frozenset({"read", "exist", "level_0", "subscriber"})

# primitive capability -> the meta capability that actually enforces ownership
PRIMITIVE_TO_META = {
    "edit_posts": "edit_post",
    "edit_others_posts": "edit_post",
    "edit_published_posts": "edit_post",
    "edit_private_posts": "edit_post",
    "delete_posts": "delete_post",
    "delete_others_posts": "delete_post",
    "publish_posts": "publish_post",
    "read": "read_post",
    "read_private_posts": "read_post",
    "edit_pages": "edit_page",
    "delete_pages": "delete_page",
    "edit_users": "edit_user",
    "list_users": "edit_user",
    "delete_users": "delete_user",
    "promote_users": "promote_user",
    "remove_users": "remove_user",
    "moderate_comments": "edit_comment",
    "edit_comment": "edit_comment",
    "manage_categories": "edit_term",
    "manage_terms": "edit_term",
    "assign_terms": "assign_term",
    "delete_terms": "delete_term",
}

META_CAPABILITIES = frozenset(PRIMITIVE_TO_META.values())

# Request-controlled sources.
SUPERGLOBALS = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER")

# WordPress functions whose FIRST argument is an object id the caller controls.
# Writing through these with a request-supplied id and no ownership check is the
# canonical CWE-639 shape.
OBJECT_WRITE_SINKS = {
    "update_post_meta": 1,
    "delete_post_meta": 1,
    "add_post_meta": 1,
    "update_user_meta": 1,
    "delete_user_meta": 1,
    "add_user_meta": 1,
    "update_term_meta": 1,
    "wp_update_post": 1,
    "wp_delete_post": 1,
    "wp_trash_post": 1,
    "wp_publish_post": 1,
    "wp_update_user": 1,
    "wp_delete_user": 1,
    "wp_set_object_terms": 1,
    "wp_update_comment": 1,
    "wp_delete_comment": 1,
    "wp_set_password": 2,
    "wp_set_current_user": 1,
}

OBJECT_READ_SINKS = {
    "get_post_meta": 1,
    "get_user_meta": 1,
    "get_userdata": 1,
    "get_post": 1,
    "get_comment": 1,
}

# Reads that disclose data about OTHER people. Missing authorization on a read
# is still CWE-862 — the tool used to rank only state-changing sinks, which left
# a handler that merely returns the site's user list behind a nonce looking
# identical to one that returns a list of post titles.
DISCLOSURE_SINKS = frozenset(
    {
        "WP_User_Query",
        "get_users",
        "wp_list_users",
        "get_user_by",
        "get_userdata",
        "get_user_meta",
        "wp_get_current_user",
        "get_comments",
        "WP_Comment_Query",
        "get_option",
        "wp_load_alloptions",
    }
)

# Reads that are only interesting when they expose other users' identities.
IDENTITY_SINKS = frozenset(
    {"WP_User_Query", "get_users", "wp_list_users", "get_user_by", "get_userdata"}
)

# Calls that change state no matter what is passed to them.
GLOBAL_WRITE_SINKS = frozenset(
    {
        "update_option",
        "delete_option",
        "add_option",
        "update_site_option",
        "wp_insert_user",
        "wp_create_user",
        "wp_set_auth_cookie",
        "wp_insert_post",
        "wp_mail",
        "file_put_contents",
        "unlink",
        "move_uploaded_file",
        "wp_handle_upload",
        "wp_delete_file",
    }
)

# Dangerous only when what reaches them is attacker-controlled. Reporting these
# unconditionally is how a scanner ends up saying "state-changing call:
# call_user_func()" about a plugin's own internal dispatch — technically a call,
# entirely useless as evidence, and it drowns the findings that matter.
TAINT_DEPENDENT_SINKS = frozenset(
    {
        "call_user_func",
        "call_user_func_array",
        "unserialize",
        "extract",
        "eval",
        "assert",
        "create_function",
        "system",
        "exec",
        "shell_exec",
        "passthru",
        "proc_open",
        "popen",
        "wp_remote_get",
        "wp_remote_post",
        "file_get_contents",
        "include",
        "require",
    }
)

_OWNERSHIP_COMPARISON = re.compile(
    r"get_current_user_id\s*\(\s*\)|wp_get_current_user\s*\(\s*\)\s*->\s*ID", re.I
)


@dataclass(frozen=True)
class Guard:
    """One check found inside a handler body."""

    function: str
    capability: str | None
    has_object_argument: bool
    line: int

    @property
    def is_capability(self) -> bool:
        return self.function in CAPABILITY_FUNCTIONS

    @property
    def is_nonce(self) -> bool:
        return self.function in NONCE_FUNCTIONS

    @property
    def is_meta(self) -> bool:
        return bool(self.capability and self.capability in META_CAPABILITIES)

    @property
    def is_weak(self) -> bool:
        return bool(self.capability and self.capability in WEAK_CAPABILITIES)


def classify(body: str, base_line: int = 1) -> tuple[list[Guard], list[str]]:
    """Guards found in a function body, plus notes about pseudo-guards."""
    from .php import blank_noncode, calls, literal

    blanked = blank_noncode(body)
    guards: list[Guard] = []
    notes: list[str] = []

    for name in sorted(CAPABILITY_FUNCTIONS | NONCE_FUNCTIONS):
        for call in calls(name, body, blanked):
            # The nonce ACTION is not always the first argument:
            # wp_verify_nonce($nonce, $action) puts it second, while
            # check_ajax_referer($action, $query_arg) puts it first. Reading
            # position 0 for both silently yielded None for wp_verify_nonce,
            # which disabled every rule keyed on the nonce action.
            position = NONCE_ACTION_POSITION.get(name, 0)
            capability = (
                literal(call.args[position]) if len(call.args) > position else None
            )
            # is_super_admin takes a user id, not a capability
            if name == "is_super_admin":
                capability = "super_admin"
            guards.append(
                Guard(
                    function=name,
                    capability=capability,
                    has_object_argument=len(call.args) > 1,
                    line=base_line + call.line - 1,
                )
            )

    for name, explanation in PSEUDO_GUARDS.items():
        if any(True for _ in calls(name, body, blanked)):
            notes.append(f"{name}(): {explanation}")

    return guards, notes


def request_controlled(body: str) -> bool:
    """True if the body reads any superglobal or REST request parameter."""
    from .php import blank_noncode

    blanked = blank_noncode(body)
    if any(name in blanked for name in SUPERGLOBALS):
        return True
    return bool(re.search(r"\$request\s*(?:\[|->\s*get_param)", blanked, re.I))


def has_ownership_comparison(body: str) -> bool:
    from .php import blank_noncode

    return bool(_OWNERSHIP_COMPARISON.search(blank_noncode(body)))


# What a sink actually touches, in the order a bug bounty program cares about.
# The recurring killer in triage is not "is there a sink" but "does reaching it
# change anything worth having". Ranking by impact rather than by presence is
# what stops a cache flush and a credential write from sharing a severity.
IMPACT_RANK = {"credentials": 0, "user_data": 1, "content": 2, "operational": 3}

_IMPACT_BY_FUNCTION = {
    "wp_set_auth_cookie": "credentials",
    "wp_set_password": "credentials",
    "wp_insert_user": "credentials",
    "wp_create_user": "credentials",
    "wp_update_user": "credentials",
    "wp_delete_user": "credentials",
    "update_user_meta": "user_data",
    "delete_user_meta": "user_data",
    "add_user_meta": "user_data",
    "get_user_meta": "user_data",
    "get_userdata": "user_data",
    "get_user_by": "user_data",
    "get_users": "user_data",
    "WP_User_Query": "user_data",
    "wp_list_users": "user_data",
    "wp_mail": "user_data",
    "wp_insert_post": "content",
    "wp_update_post": "content",
    "wp_delete_post": "content",
    "wp_trash_post": "content",
    "wp_publish_post": "content",
    "update_post_meta": "content",
    "delete_post_meta": "content",
    "add_post_meta": "content",
    "wp_update_comment": "content",
    "wp_delete_comment": "content",
    "wp_set_object_terms": "content",
    "file_put_contents": "content",
    "move_uploaded_file": "content",
    "wp_handle_upload": "content",
    "unlink": "content",
    "wp_delete_file": "content",
}

# Option names whose content is worth stealing or forging, regardless of which
# function writes them.
_SENSITIVE_OPTION = re.compile(
    r"key|token|secret|passw|licen[cs]e|api|auth|credential|smtp|salt|private",
    re.I,
)


def impact_of(function: str, option: str | None = None) -> str:
    """Impact class for a sink, refined by the option name when there is one."""
    if option and _SENSITIVE_OPTION.search(option):
        return "credentials"
    return _IMPACT_BY_FUNCTION.get(function, "operational")


@dataclass(frozen=True)
class Sink:
    function: str
    line: int
    tainted_object_id: bool
    kind: str  # "object_write" | "object_read" | "global_write" | ...
    impact: str = "operational"


_TAINT = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request\s*(?:\[|->\s*get_param)", re.I
)


def sinks(body: str, base_line: int = 1) -> list[Sink]:
    """Dangerous operations in a body, flagged when their object id is tainted.

    `tainted_object_id` is intentionally shallow: it is true when the argument
    at the object-id position mentions a superglobal or REST parameter directly.
    A value laundered through a local variable is missed — see the README's
    limits section. Shallow and honest beats deep and wrong here, because a
    false "safe" is the failure that matters.
    """
    from .php import blank_noncode, calls, literal

    blanked = blank_noncode(body)
    found: list[Sink] = []

    for name, position in OBJECT_WRITE_SINKS.items():
        for call in calls(name, body, blanked):
            argument = call.args[position - 1] if len(call.args) >= position else ""
            found.append(Sink(name, base_line + call.line - 1,
                              bool(_TAINT.search(argument)), "object_write",
                              impact_of(name)))

    for name, position in OBJECT_READ_SINKS.items():
        for call in calls(name, body, blanked):
            argument = call.args[position - 1] if len(call.args) >= position else ""
            found.append(Sink(name, base_line + call.line - 1,
                              bool(_TAINT.search(argument)), "object_read",
                              impact_of(name)))

    for name in sorted(GLOBAL_WRITE_SINKS):
        for call in calls(name, body, blanked):
            option = literal(call.args[0]) if call.args else None
            found.append(Sink(name, base_line + call.line - 1, False, "global_write",
                              impact_of(name, option)))

    for name in sorted(TAINT_DEPENDENT_SINKS):
        for call in calls(name, body, blanked):
            if any(_TAINT.search(argument) for argument in call.args):
                found.append(Sink(name, base_line + call.line - 1, True,
                                  "tainted_dispatch", "credentials"))

    for name in sorted(IDENTITY_SINKS):
        # `new WP_User_Query(...)` is a constructor, not a bare call.
        pattern = re.compile(rf"(?:new\s+)?(?<![\w$>]){re.escape(name)}\s*\(", re.I)
        for match in pattern.finditer(blanked):
            line = base_line + blanked.count("\n", 0, match.start())
            found.append(Sink(name, line, False, "identity_read", "user_data"))

    return found
