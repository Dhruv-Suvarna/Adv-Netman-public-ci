"""A line-numbered, hierarchical index over a SANITIZED running configuration.

Pure (no I/O, no Django).  Line numbers are 1-based positions in the exact text the operator sees on the
workbench's running-configuration pane (``bundles.legacy_sanitize`` output: no ``!`` / blank lines).

This is deliberately NOT an intent parser: the Phase-20.5 import parsers (``config_import.parser_*``) own the
text -> intent mapping.  They keep no line spans, which line-range removal needs, so this module indexes the same
text by indentation (EOS: 3 spaces per level; FRR: 1 space per level plus explicit ``exit`` terminators).
"""

from __future__ import annotations

from dataclasses import dataclass, field

# FRR closes blocks explicitly; EOS never does in a running config.  A terminator belongs to the block it closes.
TERMINATORS = frozenset({"exit", "exit-address-family", "exit-vrf", "exit-vni", "quit"})
PATH_SEPARATOR = " > "


def normalize(line: str) -> str:
    return " ".join(str(line).split())


@dataclass(eq=False)
class Node:
    number: int
    text: str
    indent: int
    parent: "Node | None" = None
    children: list["Node"] = field(default_factory=list)
    terminator: bool = False

    @property
    def stripped(self) -> str:
        return self.text.strip()

    def descendants(self):
        for child in self.children:
            yield child
            yield from child.descendants()

    def span(self) -> list[int]:
        return sorted([self.number, *(n.number for n in self.descendants())])

    def ancestors(self) -> list["Node"]:
        chain, cursor = [], self.parent
        while cursor is not None:
            chain.append(cursor)
            cursor = cursor.parent
        return list(reversed(chain))

    def path(self) -> str:
        return PATH_SEPARATOR.join(normalize(n.text) for n in [*self.ancestors(), self])


@dataclass
class Tree:
    roots: list[Node]
    by_number: dict[int, Node]
    line_count: int

    def node(self, number: int) -> Node | None:
        return self.by_number.get(number)


def parse(text: str) -> Tree:
    """Index ``text``.  Every non-empty line becomes exactly one Node (numbers match ``text.splitlines()``)."""
    roots: list[Node] = []
    by_number: dict[int, Node] = {}
    stack: list[Node] = []
    lines = (text or "").splitlines()
    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        node = Node(number=number, text=line, indent=indent)
        by_number[number] = node
        if line.strip() in TERMINATORS:
            # Close the innermost open block at the same or a shallower indentation, and attach the terminator to it.
            while stack and stack[-1].indent > indent:
                stack.pop()
            owner = stack.pop() if stack else None
            node.terminator = True
            if owner is not None:
                node.parent = owner
                owner.children.append(node)
            else:
                roots.append(node)
            continue
        while stack and stack[-1].indent >= indent:
            stack.pop()
        if stack:
            node.parent = stack[-1]
            stack[-1].children.append(node)
        else:
            roots.append(node)
        stack.append(node)
    return Tree(roots=roots, by_number=by_number, line_count=len(lines))


def vlan_ids(value: str) -> list[int]:
    """``10,20-22`` -> [10, 20, 21, 22]; reuses the cEOS import parser's own VLAN-list rule."""
    from ..config_import.parser_ceos import _vlan_set

    return _vlan_set(value)


def config_paths(text: str) -> frozenset[str]:
    """Header-qualified statement signatures of a SANITIZED config (used to verify presence / absence).

    A ``vlan 10,20`` stanza also yields ``vlan 10`` and ``vlan 20`` so a single VLAN's removal is checkable.
    """
    tree = parse(text)
    paths = set()
    for node in tree.by_number.values():
        if node.terminator:
            continue
        paths.add(node.path())
        stripped = node.stripped
        if node.parent is None and stripped.startswith("vlan "):
            for vid in vlan_ids(stripped.split(None, 1)[1]):
                paths.add(f"vlan {vid}")
    return frozenset(paths)
