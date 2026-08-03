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

from .php import (
    Call,
    Function,
    blank_noncode,
    calls,
    classes,
    enclosing_class,
    functions,
    literal,
    match_brace,
    property_literals,
)

# Reachability rank: how much attacker capability the entry point assumes.
# 0 = none at all, higher = more prerequisites.
REACH = {
    "unresolved": 9,
    "ajax_nopriv": 0,
    "admin_post_nopriv": 0,
    "dispatch": 0,
    "bootstrap": 1,
    "rest": 0,
    "meta": 0,
    "shortcode": 1,
    "ajax": 1,
    "admin_post": 1,
}

# Hooks that fire inside a request-DISPATCHING context before the login branch.
# admin-ajax.php and admin-post.php both call do_action('admin_init') ahead of
# their is_user_logged_in() check, so a handler here genuinely answers anonymous
# requests.
DISPATCH_HOOKS = frozenset({"admin_init"})

# Hooks that fire on essentially every request as part of loading the plugin.
# They are technically pre-authentication too, but so is every plugin's
# constructor: "runs before any authentication branch" is true of `init ->
# initHooks` and tells you nothing. Measured on 60 popular plugins, treating
# these like admin_init produced 251 of 435 high-severity findings, all of them
# bootstraps. They are tracked, and reported only when they act on request data.
BOOTSTRAP_HOOKS = frozenset(
    {
        "plugins_loaded",
        "setup_theme",
        "after_setup_theme",
        "init",
        "wp_loaded",
        "parse_request",
        "send_headers",
        "wp",
        "template_redirect",
        "login_init",
    }
)

LIFECYCLE_HOOKS = DISPATCH_HOOKS | BOOTSTRAP_HOOKS

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
    owner_class: str | None = None
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


# "wp_ajax_nopriv_{$this->action}" / "wp_ajax_{$action}" / "wp_ajax_" . $this->action
_INTERPOLATED = re.compile(
    r"^\s*[\"']"
    r"(?P<prefix>[A-Za-z_][\w]*_)"
    r"(?:\{\s*)?\$(?:this->)?(?P<prop>[A-Za-z_]\w*)"
    r"|^\s*['\"](?P<prefix2>[A-Za-z_][\w]*_)['\"]\s*\.\s*\$(?:this->)?(?P<prop2>[A-Za-z_]\w*)",
    re.S,
)


def interpolated_hook(argument: str) -> tuple[str, str, bool] | None:
    """(prefix, name, is_property) for a hook name built by interpolation.

    `is_property` distinguishes `$this->action`, whose value can be resolved
    from a class, from a bare `$action`, which inside a helper such as
    `register_ajax( $action, $callback )` is a parameter and takes whatever the
    caller passes. Treating the two alike meant every literal seen anywhere in
    the plugin was pasted into every generic registration site — one plugin
    gained four nopriv endpoints that a live $wp_filter dump says do not exist.
    """
    match = _INTERPOLATED.match(argument)
    if not match:
        return None
    prefix = match.group("prefix") or match.group("prefix2")
    prop = match.group("prop") or match.group("prop2")
    if not (prefix and prop):
        return None
    is_property = "this->" in argument
    return prefix, prop, is_property


_CONDITIONAL = re.compile(r"if\s*\(\s*\$this->([A-Za-z_]\w*)\s*\)\s*\{")


def _gating_properties(blanked: str, offset: int) -> list[str]:
    """Properties whose truthiness gates the statement at `offset`.

    A base class that registers its public hook as

        if ( $this->public ) { add_action( "wp_ajax_nopriv_{$this->action}", ... ); }

    is not saying "this endpoint is public". It is saying "this endpoint is
    public for whichever subclass sets public = true". Ignoring the condition
    invents endpoints: a live $wp_filter dump of one plugin listed 9 nopriv
    actions where ignoring it predicted 13.
    """
    gating = []
    for match in _CONDITIONAL.finditer(blanked):
        brace = match.end() - 1
        if brace < offset < match_brace(blanked, brace):
            gating.append(match.group(1))
    return gating


def _expand_interpolated(
    path: Path,
    call: Call,
    resolved: tuple[str, str],
    known: dict[str, set[str]],
    index,
    blanked: str,
    own_classes: list,
    resolve,
) -> list[EntryPoint]:
    """One entry point per class that actually produces this hook name."""
    prefix, prop, is_property = resolved
    found: list[EntryPoint] = []
    gating = _gating_properties(blanked, call.start)

    owner = enclosing_class(own_classes, call.start)
    table = getattr(index, "class_table", None) if index is not None else None

    candidates: list[tuple[str | None, str]] = []
    if table and owner and owner.name in table:
        # Ask which subclasses actually reach this registration and what each
        # sets the property to, honouring any `if ( $this->x )` gate.
        for class_name in index.descendants(owner.name):
            if any(index.resolve_bool(class_name, g) is False for g in gating):
                continue  # this subclass switches the registration off
            value = index.resolve_string(class_name, prop)
            if value:
                candidates.append((class_name, value))
    elif is_property:
        # A property with no class context: fall back to every literal seen for
        # that name. Crude, but the name still scopes it.
        candidates = [(None, value) for value in sorted(known.get(prop, ()))]
    else:
        # A bare variable in a generic helper takes whatever the caller passes.
        # There is nothing to resolve, and guessing invents endpoints.
        return []

    seen: set[str] = set()
    for class_name, value in candidates:
        candidate = prefix + value
        if candidate in seen:
            continue
        seen.add(candidate)
        kind = _hook_kind(candidate)
        if not kind:
            continue
        entry = resolve(
            EntryPoint(
                kind=kind[0],
                hook=candidate,
                callback=callback_name(call.args[1]),
                file=path,
                line=call.line,
                owner_class=class_name,
            )
        )
        entry.notes.append(
            f"hook name resolved from ${prop}"
            + (f" on {class_name}" if class_name else "")
            + "; the literal never appears in the source"
        )
        found.append(entry)

    return found


def scan_file(
    path: Path, source: str, properties: dict[str, set[str]] | None = None, index=None
) -> list[EntryPoint]:
    """Entry points in one file.

    `properties` maps class-property names to the literals assigned to them
    anywhere in the project, so a hook registered as
    `add_action("wp_ajax_nopriv_{$this->action}", ...)` can still be resolved.
    Without it, only same-file properties are available.
    """
    blanked = blank_noncode(source)
    defined = functions(source, blanked)
    by_name: dict[str, Function] = {}
    for function in defined:
        by_name.setdefault(function.name, function)

    own_classes = classes(source, blanked)

    known = dict(property_literals(source, blanked))
    for name, values in (properties or {}).items():
        known.setdefault(name, set()).update(values)

    found: list[EntryPoint] = []
    unresolved: list[str] = []

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
            resolved = interpolated_hook(call.args[0])
            if resolved:
                expanded = _expand_interpolated(
                    path, call, resolved, known, index, blanked, own_classes, resolve
                )
                if expanded:
                    found.extend(expanded)
                else:
                    unresolved.append(call.args[0][:60])
                continue
            unresolved.append(call.args[0][:60])
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
                    kind="dispatch" if hook in DISPATCH_HOOKS else "bootstrap",
                    hook=hook,
                    callback=callback_name(call.args[1]),
                    file=path,
                    line=call.line,
                )
            )
            if hook in DISPATCH_HOOKS:
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

    # Hook names this pass could not resolve are coverage the tool does not
    # have. Recording them beats dropping them silently: an unresolved hook is
    # exactly where a missed entry point hides.
    for raw in unresolved:
        entry = EntryPoint(
            kind="unresolved", hook=raw, callback="?", file=path, line=0
        )
        entry.notes.append("dynamic hook name — not analysed")
        found.append(entry)

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
