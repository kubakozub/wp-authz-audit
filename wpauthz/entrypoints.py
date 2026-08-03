"""Find every place a request from outside can enter a WordPress plugin.

The point of this module is triage speed. A mid-sized plugin is tens of
thousands of lines, but the code an unauthenticated request can actually reach
is usually a couple of dozen callbacks. Enumerating those first turns "read the
plugin" into "read these twenty functions", which is the whole game.

Entry point kinds, and who can reach them:

  ajax_nopriv    add_action('wp_ajax_nopriv_x', ...)   anyone, no login
  ajax           add_action('wp_ajax_x', ...)          any logged-in user,
                                                       including subscriber
  rest           register_rest_route(...)              per permission_callback
  admin_post_nopriv  admin_post_nopriv_x               anyone, no login
  admin_post     admin_post_x                          any logged-in user
  lifecycle      add_action('init'|'admin_init'|...)   anyone, no login
  shortcode      add_shortcode(...)                    any author of content
  meta           register_post_meta(... show_in_rest)  per auth_callback

`ajax` matters as much as `ajax_nopriv`: "logged in" on a site with open
registration, WooCommerce customers, or subscribers is not an authorization
boundary. Missing capability checks there are the classic privilege escalation.

`lifecycle` is the one people get wrong. `admin_init` sounds administrative, but
both wp-admin/admin-ajax.php and wp-admin/admin-post.php fire `do_action(
'admin_init')` BEFORE they branch on `is_user_logged_in()`. An admin_init
handler that reads `$_GET` and acts on it is reachable by an anonymous request.
Handlers on these hooks are only reported when they actually read request data —
otherwise every plugin would produce dozens of empty findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .php import Call, Function, blank_noncode, calls, functions, literal

# Reachability rank: how much attacker capability the entry point assumes.
# 0 = none at all, higher = more prerequisites.
REACH = {
    "ajax_nopriv": 0,
    "admin_post_nopriv": 0,
    "lifecycle": 0,
    "rest": 0,
    "meta": 0,
    "shortcode": 1,
    "ajax": 1,
    "admin_post": 1,
}

# Hooks that run before, or independently of, any authentication branch.
# admin_init is here deliberately: admin-ajax.php and admin-post.php both fire
# it ahead of their is_user_logged_in() check.
LIFECYCLE_HOOKS = frozenset(
    {
        "plugins_loaded",
        "setup_theme",
        "after_setup_theme",
        "init",
        "admin_init",
        "wp_loaded",
        "parse_request",
        "send_headers",
        "wp",
        "template_redirect",
        "login_init",
    }
)

_HOOK_PREFIXES = (
    ("wp_ajax_nopriv_", "ajax_nopriv"),
    ("wp_ajax_", "ajax"),
    ("admin_post_nopriv_", "admin_post_nopriv"),
    ("admin_post_", "admin_post"),
)


@dataclass
class EntryPoint:
    kind: str
    hook: str
    callback: str
    file: Path
    line: int
    permission_callback: str | None = None
    resolved: Function | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def reach(self) -> int:
        return REACH.get(self.kind, 2)


_CALLBACK_ARRAY = re.compile(
    r"^\s*(?:array\s*\(|\[)\s*(\$this|self::class|__CLASS__|[A-Za-z_][\w\\]*::class|'[^']+'|\"[^\"]+\")\s*,\s*['\"]([A-Za-z_]\w*)['\"]",
    re.S,
)
_CALLBACK_STATIC = re.compile(r"^\s*['\"]([A-Za-z_][\w\\]*)::([A-Za-z_]\w*)['\"]\s*$")


def callback_name(argument: str) -> str:
    """Human-readable callback target from an add_action/route argument."""
    argument = argument.strip()

    plain = literal(argument)
    if plain and "::" not in plain:
        return plain

    match = _CALLBACK_STATIC.match(argument)
    if match:
        return f"{match.group(1)}::{match.group(2)}"

    match = _CALLBACK_ARRAY.match(argument)
    if match:
        owner = match.group(1).strip("'\"")
        return f"{owner}::{match.group(2)}"

    if argument.startswith(("function", "fn", "static function")):
        return "<closure>"

    return argument.replace("\n", " ")[:60]


def method_of(callback: str) -> str:
    """Bare method/function name, for matching against a definition."""
    return callback.rsplit("::", 1)[-1]


def _hook_kind(hook: str) -> tuple[str, str] | None:
    for prefix, kind in _HOOK_PREFIXES:
        if hook.startswith(prefix) and len(hook) > len(prefix):
            return kind, hook
    return None


def scan_file(path: Path, source: str) -> list[EntryPoint]:
    blanked = blank_noncode(source)
    defined = functions(source, blanked)
    by_name: dict[str, Function] = {}
    for function in defined:
        by_name.setdefault(function.name, function)

    found: list[EntryPoint] = []

    def resolve(entry: EntryPoint) -> EntryPoint:
        target = by_name.get(method_of(entry.callback))
        if target:
            entry.resolved = target
        elif entry.callback == "<closure>":
            entry.notes.append("closure callback: body analysed in place")
        else:
            entry.notes.append("callback not defined in this file")
        return entry

    for call in calls("add_action", source, blanked):
        if len(call.args) < 2:
            continue
        hook = literal(call.args[0])
        if not hook:
            continue
        kind = _hook_kind(hook)
        if kind:
            found.append(
                resolve(
                    EntryPoint(
                        kind=kind[0],
                        hook=hook,
                        callback=callback_name(call.args[1]),
                        file=path,
                        line=call.line,
                    )
                )
            )
        elif hook in LIFECYCLE_HOOKS:
            entry = resolve(
                EntryPoint(
                    kind="lifecycle",
                    hook=hook,
                    callback=callback_name(call.args[1]),
                    file=path,
                    line=call.line,
                )
            )
            if hook == "admin_init":
                entry.notes.append(
                    "admin_init also fires on admin-ajax.php and admin-post.php "
                    "before the login branch"
                )
            found.append(entry)

    for call in calls("add_shortcode", source, blanked):
        if len(call.args) < 2:
            continue
        tag = literal(call.args[0]) or "<dynamic>"
        found.append(
            resolve(
                EntryPoint(
                    kind="shortcode",
                    hook=tag,
                    callback=callback_name(call.args[1]),
                    file=path,
                    line=call.line,
                )
            )
        )

    found.extend(_rest_routes(path, source, blanked, resolve))
    found.extend(_registered_meta(path, source, blanked))
    return found


_META_REGISTRARS = ("register_post_meta", "register_term_meta", "register_meta")


def _registered_meta(path: Path, source: str, blanked: str) -> list[EntryPoint]:
    """Meta keys exposed to REST whose auth_callback waves everything through.

    With show_in_rest true and auth_callback returning true, any user who can
    reach the object's REST endpoint can write that meta key. Omitting
    auth_callback is safe — core defaults to a capability check — so only an
    explicit permissive callback is a finding.
    """
    found: list[EntryPoint] = []

    for registrar in _META_REGISTRARS:
        for call in calls(registrar, source, blanked):
            if not call.args:
                continue
            options = call.args[-1]
            if "show_in_rest" not in options:
                continue
            auth = _assoc_value(options, "auth_callback")
            if not auth:
                continue
            # All three registrars take (object_type, meta_key, args), so the
            # key is the SECOND argument. Taking the first literal instead
            # yields the object type, which makes every finding read as "post".
            key = literal(call.args[1]) if len(call.args) > 1 else None
            key = key or "<dynamic>"
            entry = EntryPoint(
                kind="meta",
                hook=f"{registrar}:{key}",
                callback=callback_name(auth),
                file=path,
                line=call.line,
                permission_callback=auth.strip(),
            )
            entry.notes.append("exposed to REST via show_in_rest")
            found.append(entry)

    return found


_ARG_KEY = re.compile(r"['\"](\w+)['\"]\s*=>\s*", re.S)


def _assoc_value(block: str, key: str) -> str | None:
    """Value for `'key' => ...` inside an array literal, as raw source."""
    match = re.search(rf"['\"]{re.escape(key)}['\"]\s*=>\s*", block)
    if not match:
        return None
    rest = block[match.end() :]
    depth, out = 0, []
    for ch in rest:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        out.append(ch)
    return "".join(out).strip() or None


def _rest_routes(path: Path, source: str, blanked: str, resolve) -> list[EntryPoint]:
    found: list[EntryPoint] = []

    for call in calls("register_rest_route", source, blanked):
        if len(call.args) < 3:
            continue
        namespace = literal(call.args[0]) or call.args[0]
        route = literal(call.args[1]) or call.args[1]
        options = call.args[2]

        # A route may register one handler or a list of them; treat the whole
        # options blob per 'callback' occurrence so multi-method routes are not
        # collapsed into one finding.
        segments = _split_handlers(options)
        for segment in segments:
            callback = _assoc_value(segment, "callback")
            permission = _assoc_value(segment, "permission_callback")
            methods = _assoc_value(segment, "methods") or ""
            entry = EntryPoint(
                kind="rest",
                hook=f"{namespace}{route}".replace("''", ""),
                callback=callback_name(callback) if callback else "<none>",
                file=path,
                line=call.line,
                permission_callback=permission.strip() if permission else None,
            )
            if methods:
                entry.notes.append(f"methods: {methods.strip()[:40]}")
            found.append(resolve(entry))

    return found


def _split_handlers(options: str) -> list[str]:
    """One segment per 'callback' key, so each handler is judged separately."""
    positions = [m.start() for m in re.finditer(r"['\"]callback['\"]\s*=>", options)]
    if len(positions) <= 1:
        return [options]
    bounds = positions + [len(options)]
    segments = []
    for index in range(len(positions)):
        start = options.rfind("[", 0, bounds[index])
        start = max(start, options.rfind("(", 0, bounds[index]))
        segments.append(options[max(start, 0) : bounds[index + 1]])
    return segments


PHP_SUFFIXES = {".php", ".inc"}
SKIP_DIRS = {"node_modules", "vendor", ".git", "tests", "test", "__tests__"}


def iter_php(root: Path, include_vendor: bool = False):
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in PHP_SUFFIXES or not path.is_file():
            continue
        parts = set(path.relative_to(root).parts[:-1])
        if not include_vendor and parts & SKIP_DIRS:
            continue
        yield path


def scan_tree(root: Path, include_vendor: bool = False) -> list[EntryPoint]:
    found: list[EntryPoint] = []
    for path in iter_php(root, include_vendor):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found.extend(scan_file(path, source))
    return found
