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

# State-changing sinks that are dangerous regardless of any object id.
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
        "wp_remote_get",
        "wp_remote_post",
        "file_put_contents",
        "unlink",
        "move_uploaded_file",
        "wp_handle_upload",
        "wp_delete_file",
        "eval",
        "unserialize",
        "extract",
        "call_user_func",
        "call_user_func_array",
        "system",
        "exec",
        "shell_exec",
        "passthru",
        "proc_open",
        "popen",
        "assert",
        "create_function",
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
            capability = literal(call.args[0]) if call.args else None
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


@dataclass(frozen=True)
class Sink:
    function: str
    line: int
    tainted_object_id: bool
    kind: str  # "object_write" | "object_read" | "global_write"


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
    from .php import blank_noncode, calls

    blanked = blank_noncode(body)
    found: list[Sink] = []

    for name, position in OBJECT_WRITE_SINKS.items():
        for call in calls(name, body, blanked):
            argument = call.args[position - 1] if len(call.args) >= position else ""
            found.append(
                Sink(name, base_line + call.line - 1, bool(_TAINT.search(argument)), "object_write")
            )

    for name, position in OBJECT_READ_SINKS.items():
        for call in calls(name, body, blanked):
            argument = call.args[position - 1] if len(call.args) >= position else ""
            found.append(
                Sink(name, base_line + call.line - 1, bool(_TAINT.search(argument)), "object_read")
            )

    for name in sorted(GLOBAL_WRITE_SINKS):
        for call in calls(name, body, blanked):
            found.append(Sink(name, base_line + call.line - 1, False, "global_write"))

    return found
