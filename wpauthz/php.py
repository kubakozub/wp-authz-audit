"""Minimal PHP source model: enough structure to follow a hook to its callback.

This is deliberately NOT a PHP parser. A real parser (php-parser, tree-sitter)
would be more accurate, but pulling a PHP toolchain into an offline Python tool
costs more than it returns for the one question this asks: "which function runs
when this hook fires, and does that function check anything before acting?"

What it does give you, and why each piece is load-bearing:

  * `blank_noncode()` replaces the contents of comments and string literals with
    filler of the same length. Every offset stays valid, but a match can no
    longer land inside a docblock or a string. Without this step, a plugin that
    merely mentions `current_user_can` in a comment reads as protected — and a
    tool that says "protected" when it means "the words appear nearby" is worse
    than no tool.
  * `functions()` finds function and method definitions with their real body
    extents by brace matching over the blanked source, so nested braces, braces
    in strings, and `${...}` interpolation do not truncate a body.
  * `calls()` finds call sites with balanced-paren argument extraction, so a
    callback argument containing its own parentheses or commas survives intact.

Known limits are in the module docstring of `authz.py` and in the README; they
are part of the contract, not omissions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

_LINE_COMMENT = re.compile(r"//|#")
_OPEN_BLOCK = "/*"


def blank_noncode(source: str) -> str:
    """Return source with comment and string CONTENTS replaced by spaces.

    Length and every offset are preserved, so line numbers and slices computed
    on the result apply unchanged to the original. Quotes and comment markers
    themselves are kept, which keeps the result readable when debugging.
    """
    out = list(source)
    i, n = 0, len(source)

    while i < n:
        ch = source[i]

        # Block comment
        if source.startswith(_OPEN_BLOCK, i):
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for j in range(i + 2, min(end - 2, n)):
                if out[j] != "\n":
                    out[j] = " "
            i = end
            continue

        # Line comment. '#[' opens a PHP 8 attribute, not a comment.
        if ch == "/" and i + 1 < n and source[i + 1] == "/" or (
            ch == "#" and not source.startswith("#[", i)
        ):
            end = source.find("\n", i)
            end = n if end == -1 else end
            for j in range(i, end):
                out[j] = " "
            i = end
            continue

        # Heredoc / nowdoc
        if source.startswith("<<<", i):
            match = re.match(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1\r?\n", source[i:])
            if match:
                label = match.group(2)
                body_start = i + match.end()
                close = re.compile(rf"^[ \t]*{label}\b", re.M)
                found = close.search(source, body_start)
                end = found.start() if found else n
                for j in range(body_start, min(end, n)):
                    if out[j] != "\n":
                        out[j] = " "
                i = end if found else n
                continue

        # Quoted string
        if ch in "'\"":
            quote = ch
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == quote:
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = min(j + 1, n)
            continue

        i += 1

    return "".join(out)


def line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def match_brace(blanked: str, open_index: int) -> int:
    """Index just past the '}' matching the '{' at open_index (or len)."""
    depth = 0
    for i in range(open_index, len(blanked)):
        if blanked[i] == "{":
            depth += 1
        elif blanked[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(blanked)


def _match_paren(blanked: str, open_index: int) -> int:
    depth = 0
    for i in range(open_index, len(blanked)):
        if blanked[i] == "(":
            depth += 1
        elif blanked[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def split_args(raw: str) -> list[str]:
    """Split an argument list on top-level commas only."""
    args, depth, current = [], 0, []
    for ch in raw:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


@dataclass(frozen=True)
class Function:
    name: str
    qualified: str
    start: int
    body_start: int
    body_end: int
    line: int
    params: str = ""

    def body(self, source: str) -> str:
        return source[self.body_start : self.body_end]

    @property
    def required_arity(self) -> int:
        """Parameters with no default and no variadic — what PHP demands."""
        if not self.params.strip():
            return 0
        count = 0
        for parameter in split_args(self.params):
            if "=" in parameter or "..." in parameter:
                continue
            if "$" in parameter:
                count += 1
        return count


_FUNC_RE = re.compile(r"\bfunction\s+&?\s*([A-Za-z_]\w*)\s*\(", re.I)
_CLASS_RE = re.compile(r"\b(?:class|trait)\s+([A-Za-z_]\w*)", re.I)


def functions(source: str, blanked: str | None = None) -> list[Function]:
    """Every named function/method with its true body extent."""
    blanked = blank_noncode(source) if blanked is None else blanked

    classes: list[tuple[int, int, str]] = []
    for match in _CLASS_RE.finditer(blanked):
        brace = blanked.find("{", match.end())
        if brace == -1:
            continue
        classes.append((brace, match_brace(blanked, brace), match.group(1)))

    found: list[Function] = []
    for match in _FUNC_RE.finditer(blanked):
        paren_close = _match_paren(blanked, match.end() - 1)
        if paren_close == -1:
            continue
        brace = blanked.find("{", paren_close)
        if brace == -1:
            continue
        # An abstract/interface method ends at ';' before any '{'
        semi = blanked.find(";", paren_close)
        if semi != -1 and semi < brace:
            continue

        name = match.group(1)
        owner = next(
            (cls for start, end, cls in classes if start < match.start() < end), None
        )
        found.append(
            Function(
                name=name,
                qualified=f"{owner}::{name}" if owner else name,
                start=match.start(),
                body_start=brace,
                body_end=match_brace(blanked, brace),
                line=line_of(source, match.start()),
                params=source[match.end() : paren_close],
            )
        )
    return found


# `var $action = 'x';`, `public $action = 'x';`, `protected string $a = 'x';`
_PROPERTY_RE = re.compile(
    r"\b(?:var|public|protected|private)\s+(?:static\s+)?(?:\??\w+\s+)?"
    r"\$([A-Za-z_]\w*)\s*=\s*(['\"])([^'\"]*)\2\s*;",
)


_CLASS_DECL_RE = re.compile(
    r"\b(?:abstract\s+|final\s+)*class\s+([A-Za-z_]\w*)"
    r"(?:\s+extends\s+([A-Za-z_][\w\\]*))?",
    re.I,
)

# `var $public = false;`, `public $public = true;`, `protected bool $x = true;`
_BOOL_PROPERTY_RE = re.compile(
    r"\b(?:var|public|protected|private)\s+(?:static\s+)?(?:\??\w+\s+)?"
    r"\$([A-Za-z_]\w*)\s*=\s*(true|false)\s*;",
    re.I,
)


@dataclass
class ClassInfo:
    name: str
    parent: str | None
    start: int
    end: int
    strings: dict[str, str]
    booleans: dict[str, bool]
    methods: dict[str, str]


def classes(source: str, blanked: str | None = None) -> list[ClassInfo]:
    """Classes with their parent, own property literals, and method bodies.

    Inheritance matters more here than it looks. A base class registering a hook
    behind `if ( $this->public )` is not a statement about the base class — it is
    a statement about whichever subclass is instantiated. Reading the property
    from the base and applying it to every descendant reports endpoints that do
    not exist; resolving it per subclass is the difference between a list of
    entry points and a list of guesses.
    """
    blanked = blank_noncode(source) if blanked is None else blanked
    found: list[ClassInfo] = []

    for match in _CLASS_DECL_RE.finditer(blanked):
        brace = blanked.find("{", match.end())
        if brace == -1:
            continue
        end = match_brace(blanked, brace)
        body = source[brace:end]
        blanked_body = blanked[brace:end]

        strings = {
            m.group(1): m.group(3)
            for m in _PROPERTY_RE.finditer(body)
            if m.group(3)
        }
        booleans = {
            m.group(1): m.group(2).lower() == "true"
            for m in _BOOL_PROPERTY_RE.finditer(blanked_body)
        }
        methods = {
            function.name: function.body(source)
            for function in functions(source, blanked)
            if brace < function.start < end
        }

        found.append(
            ClassInfo(
                name=match.group(1),
                parent=match.group(2).rsplit("\\", 1)[-1] if match.group(2) else None,
                start=match.start(),
                end=end,
                strings=strings,
                booleans=booleans,
                methods=methods,
            )
        )

    return found


def enclosing_class(infos: list[ClassInfo], offset: int) -> ClassInfo | None:
    for info in infos:
        if info.start < offset < info.end:
            return info
    return None


def property_literals(source: str, blanked: str | None = None) -> dict[str, set[str]]:
    """Class properties assigned a string literal, by property name.

    WordPress plugins routinely register hooks from a property rather than a
    literal — `add_action( "wp_ajax_nopriv_{$this->action}", ... )` in a base
    class, with each subclass setting `var $action = '...'`. The literal hook
    name never appears in the source, so a purely literal scan is blind to the
    entry point entirely. Collecting the property values makes those hooks
    resolvable.
    """
    blanked = blank_noncode(source) if blanked is None else blanked
    values: dict[str, set[str]] = {}
    # Match on the original source: the values ARE string contents, which the
    # blanked copy has erased. Guard against comments by checking the blanked
    # copy still has code at that offset.
    for match in _PROPERTY_RE.finditer(source):
        if blanked[match.start() : match.start() + 3].isspace():
            continue
        if match.group(3):
            values.setdefault(match.group(1), set()).add(match.group(3))
    return values


@dataclass(frozen=True)
class Call:
    name: str
    args: list[str]
    start: int
    line: int


def calls(name: str, source: str, blanked: str | None = None) -> Iterator[Call]:
    """Call sites of `name`, with arguments taken from the ORIGINAL source.

    Matching happens on the blanked copy so a call named inside a comment or a
    string is never reported, but arguments are sliced from the real source so
    string literals in them stay readable.
    """
    blanked = blank_noncode(source) if blanked is None else blanked
    pattern = re.compile(rf"(?<![\w$>:]){re.escape(name)}\s*\(", re.I)

    for match in pattern.finditer(blanked):
        close = _match_paren(blanked, match.end() - 1)
        if close == -1:
            continue
        yield Call(
            name=name,
            args=split_args(source[match.end() : close]),
            start=match.start(),
            line=line_of(source, match.start()),
        )


_STRING_LITERAL = re.compile(r"^\s*(['\"])(.*)\1\s*$", re.S)


def literal(argument: str) -> str | None:
    """The value of a single-quoted or double-quoted literal, else None."""
    match = _STRING_LITERAL.match(argument)
    if not match:
        return None
    value = match.group(2)
    if "$" in value and match.group(1) == '"':
        return None  # interpolated: not a constant we can trust
    return value
