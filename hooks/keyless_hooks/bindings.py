"""Variables a command binds to a literal, PROVABLY, before a given offset.

`P=/api/v1/…/services/loki:3100/proxy/loki/api/v1; kubectl get --raw "$P/labels"`
reads Loki's label list. KL-VAULT refused it as an unprovable Secret read, because
`$P` is a variable and a variable can hold anything — which is true of a variable
nobody in this text assigned, and false of one assigned a literal two statements
earlier. This module tells those apart.

It is NOT `shellview.expand_local_assignments`, and the difference is the
direction each one fails in. That helper feeds a BLOCK-ward scan: KL-FILE scans
its expansion AS WELL AS the raw text, so an expansion that is wrong can only add
a refusal. This one REMOVES a refusal, so a wrong answer here is a Secret read
let through. It therefore answers only when the shell's own semantics leave no
alternative, and returns nothing — the old, refusing reading — whenever:

  - any construct in the text can rebind or scope a variable out of sight: a
    loop, a conditional, a function, a subshell or group, `eval`, `source`/`.`,
    `read`, `declare` and its kin. One such construct anywhere resolves nothing;
  - the name has more than one binding site, or occurs as a bare word anywhere
    except its one assignment (`read P`, `P+=x`, `printf -v P`, `unset P`, a
    prefix assignment `P=x cmd`, whose own words never see it);
  - the assignment is not an unconditional statement of the current shell — it
    follows `&&`, `||`, `|` or `&`, or is piped or backgrounded;
  - the value is not a plain literal: any `$`, backtick, `~`, glob character,
    brace, whitespace or backslash;
  - an expansion carries an operator (`${P:-…}`, `${P#…}`), which decides the
    value at run time.

A binding counts for a statement only when the assignment ENDS before that
statement starts, so a use ahead of its assignment still expands whatever the
environment held.

debt: a shell function or alias defined OUTSIDE this text — in a profile or a
      shell snapshot — and called between the assignment and the use could
      reassign the name, and nothing in the text shows it. Ceiling: such a
      function rebinding a name to a Secret path between two statements of one
      command. Upgrade trigger: a transcript shows a Secret rendered by a
      `--raw` call whose path came through a resolved binding.
"""

import re

from .shellview import (assignment_split, head_of, statement_spans, stripped,
                        words)

__all__ = ["literal_bindings", "resolve"]


# Heads that bind, scope or re-read a name, or run code this text cannot see.
_BAIL_HEADS = frozenset([
    "eval", "source", ".", "read", "mapfile", "readarray", "getopts", "declare",
    "typeset", "local", "readonly", "unset", "alias", "function", "for",
    "select", "case", "esac", "while", "until", "if", "then", "else", "elif",
    "fi", "do", "done", "trap", "let", "vared", "zparseopts",
])

_KEYWORD = re.compile(
    r"(?:^|[\s;&|])(?:for|select|case|while|until|if|function|do|done|fi|esac)(?=[\s;&|]|$)")

# A literal value, optionally wrapped whole in one kind of quote.
_LITERAL = re.compile(r"[A-Za-z0-9_./:%=+,@-]*")

_NAME_CHARS = "A-Za-z0-9_"

_PARAM = re.compile(r"\$\{[^{}()]*\}")

_MAX_NAMES = 64


def _plain_value(raw):
    """The value a literal assignment stores, or None when it is not one."""
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        raw = raw[1:-1]
    return raw if _LITERAL.fullmatch(raw) else None


def _left_separator(view, start):
    j = start - 1
    while j >= 0 and view[j] in " \t":
        j -= 1
    if j < 0:
        return ""
    if view[j] in "&|" and j > 0 and view[j - 1] == view[j]:
        return view[j] * 2
    return view[j]


def _right_separator(view, end):
    j = end
    n = len(view)
    while j < n and view[j] in " \t":
        j += 1
    if j >= n:
        return ""
    if view[j] in "&|" and j + 1 < n and view[j + 1] == view[j]:
        return view[j] * 2
    return view[j]


def _assignment_statement(stmt):
    """[(name, value or None, name offset in stmt)] when every word of `stmt` is an
    assignment (optionally after `export`), else None."""
    spans = words(stmt)
    if not spans:
        return None
    declared = stmt[spans[0][0]:spans[0][1]] == "export"
    if declared:
        spans = spans[1:]
        if not spans:
            return None
    out = []
    for a, b in spans:
        pair = assignment_split(stmt[a:b], declared=declared)
        if pair is None or not re.fullmatch(r"[A-Za-z_][%s]*" % _NAME_CHARS, pair[0]):
            return None
        if not stmt[a:b].startswith(pair[0] + "="):
            # A name assembled from quotes after `export` is real, and is also not
            # the spelling any use in this text would carry. Not provable.
            return None
        out.append((pair[0], _plain_value(pair[1]), a))
    return out


def literal_bindings(text):
    """{name: (value, end offset of its assignment statement)} for every name this
    text binds to a literal, provably — see the module docstring for what
    disqualifies one. `text` is the view the caller will slice statements from,
    with substitutions already made opaque, so a `$( … )` assigns nothing here."""
    if not text or "=" not in text:
        return {}
    view = stripped(text)
    # A parameter expansion's braces are not a group; every other `(`, `)`, `{`
    # or `}` left on the stripped view opens or closes a subshell, a group, a
    # function body or arithmetic, any of which can rebind a name out of sight.
    groups = _PARAM.sub(lambda m: " " * len(m.group(0)), view)
    if re.search(r"[(){}]", groups) or _KEYWORD.search(view):
        return {}
    spans = statement_spans(text)
    sites = {}
    for start, end in spans:
        stmt = text[start:end]
        assigns = _assignment_statement(stmt)
        if assigns is None:
            if head_of(stmt) in _BAIL_HEADS:
                return {}
            continue
        unconditional = (_left_separator(view, start) in ("", ";", "\n")
                         and _right_separator(view, end) in ("", ";", "\n", "&&", "||"))
        for name, value, off in assigns:
            sites.setdefault(name, []).append(
                (value if unconditional else None, start + off, end))
        if len(sites) > _MAX_NAMES:
            return {}

    out = {}
    for name, found in sites.items():
        if len(found) != 1 or found[0][0] is None:
            continue
        value, name_at, end = found[0]
        if _only_reads_elsewhere(text, name, name_at):
            out[name] = (value, end)
    return out


def _only_reads_elsewhere(text, name, name_at):
    """True when every occurrence of `name` in `text`, other than its assignment at
    `name_at`, is a plain `$name` or `${name}` read."""
    for m in re.finditer(r"(?<![%s])%s(?![%s])" % (_NAME_CHARS, re.escape(name), _NAME_CHARS),
                         text):
        i = m.start()
        if i == name_at:
            continue
        if i >= 1 and text[i - 1] == "$":
            continue
        if i >= 2 and text[i - 2:i] == "${" and text[m.end():m.end() + 1] == "}":
            continue
        return False
    return True


def resolve(text, bindings, before):
    """`text` with every `$name` / `${name}` replaced by its literal, for the names
    whose assignment ends at or before offset `before`."""
    live = {k: v for k, (v, end) in bindings.items() if end <= before}
    if not live:
        return text

    def sub(m):
        key = m.group(1) or m.group(2)
        return live.get(key, m.group(0))

    return re.sub(r"\$\{([A-Za-z_][%s]*)\}|\$([A-Za-z_][%s]*)(?![%s])"
                  % (_NAME_CHARS, _NAME_CHARS, _NAME_CHARS), sub, text)
