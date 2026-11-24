"""Interprocedural control-flow graph.

The static stage does not inline function bodies into copies of the source. It walks the CFGs of
all functions and modifiers of a contract and adds two kinds of interprocedural edge:

* call edge: a call node -> the entry point of the callee;
* return edge: an exit of the callee -> the node after the call.

Return edges are matched against a call stack, so only *valid paths* are explored: a callee
reached from one call site never returns into another. The expansion is produced per entry point
and is not stored on the contract.

Modifiers are part of the graph. Slither keeps a modifier body in a separate CFG and leaves a
marker node `onlyOwner()` in the function, with a direct edge to the function body. That direct
edge is suppressed here, otherwise the body would be reachable without the guard and dominance
would be wrong. The `_` of a modifier is a `PLACEHOLDER` node and behaves like a call to the
continuation of the marker node: entering it runs the function body, and returning from the body
lands on the code after `_`.

Recursion is not unrolled. A call edge into a function already present on the current chain is
not taken; the call node keeps its ordinary intraprocedural edge instead.

Everything the method needs from the graph is computed here: reachability from an entry point,
dominance (for G_t and g), N*_t and b(t) (2.19), and the distance used by the worklist.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterator, Optional

from slither.core.cfg.node import Node, NodeType
from slither.core.declarations import Contract, Function, Modifier
from slither.slithir.operations import InternalCall, LibraryCall, SolidityCall

#: Node types that branch, plus `require` / `assert`, which Slither models as an EXPRESSION node
#: holding a SolidityCall. Both count towards b(t): the revert branch is a second outcome.
_BRANCH_NODE_TYPES = frozenset({NodeType.IF, NodeType.IFLOOP})
_REQUIRE_SIGNATURES = frozenset(
    {
        "require(bool)",
        "require(bool,string)",
        "require(bool,error)",
        "assert(bool)",
    }
)


def inlined_callee(ir) -> Optional[Function]:
    """The function this IR inlines into the caller, or None if it is not an inlined call.

    Two cases are compiler-inlined and therefore modelled exactly by walking into the body rather
    than by an opaque result:

    * an ordinary `InternalCall`;
    * a call to an *internal* (or private) library function -- classic SafeMath, which solc copies
      straight into the contract, so inlining it is an exact model and not an extension of the method.

    A public or external library function is a DELEGATECALL to a separate contract whose code is
    unknown. It is left opaque (the translator binds a fresh result) and is not inlined here.
    """
    function = getattr(ir, "function", None)
    if not isinstance(function, Function) or not function.is_implemented:
        return None
    if isinstance(ir, LibraryCall):
        return function if function.visibility in ("internal", "private") else None
    if isinstance(ir, InternalCall):
        return function
    return None


def next_inlined_call(node: Node, start: int = 0) -> Optional[tuple[int, Function]]:
    """The first inlined call at index >= `start` in the node, as (index, callee), or None."""
    for index in range(start, len(node.irs)):
        callee = inlined_callee(node.irs[index])
        if callee is not None:
            return index, callee
    return None


def is_branching(node: Node) -> bool:
    """True if the node contributes to b(t)."""
    if node.type in _BRANCH_NODE_TYPES:
        return True
    return any(
        isinstance(ir, SolidityCall) and ir.function.full_name in _REQUIRE_SIGNATURES
        for ir in node.irs
    )


def _function_key(function: Function) -> str:
    return function.canonical_name


def _node_key(node: Node) -> tuple[str, int]:
    return (_function_key(node.function), node.node_id)


@dataclass(frozen=True)
class Frame:
    """One entry of the call stack.

    `site_key` is the node that transferred control. `returns_to` is where the callee returns: a
    `(node_key, resume)` pair, so a return can land back inside the same node at the index after the
    call -- which is what a chained call `a.add(b).sub(c)` needs, two inlined calls in one node. It
    is None when the callee is the last thing the caller does, as for a modifier marker node, whose
    continuation already ran through the placeholder.
    """

    site_key: tuple[str, int]
    callee_key: str
    returns_to: Optional[tuple[tuple[str, int], int]]
    #: Modifiers and the body entered through `_` are always inlined, whatever d is, so those
    #: frames do not count towards the inlining depth.
    counts_towards_depth: bool = True


@dataclass(frozen=True)
class Vertex:
    """A node together with the call stack it was reached under.

    `resume` is the IR index the node is entered at. It is 0 for an ordinary visit and > 0 when the
    node is re-entered after returning from an inlined call it contains, so that the operations
    between two chained calls, and after the last one, run exactly once and in order.
    """

    node_key: tuple[str, int]
    stack: tuple[Frame, ...]
    resume: int = 0

    @property
    def depth(self) -> int:
        """Inlining depth from the entry point; modifier frames do not count."""
        return sum(1 for frame in self.stack if frame.counts_towards_depth)


class Expansion:
    """Valid-path expansion of the ICFG from one entry point."""

    def __init__(self, entry_point: Function) -> None:
        self.entry_point = entry_point
        self._nodes: dict[tuple[str, int], Node] = {}
        self._successors: dict[Vertex, list[Vertex]] = {}
        self._predecessors: dict[Vertex, list[Vertex]] = {}
        self.root = Vertex(_node_key(entry_point.entry_point), ())
        self._build()

    # ---------------------------------------------------------------- building

    def _build(self) -> None:
        self._register(self.entry_point)
        work: deque[Vertex] = deque([self.root])
        self._successors[self.root] = []
        self._predecessors[self.root] = []
        seen = {self.root}
        while work:
            vertex = work.popleft()
            for successor in self._step(vertex):
                self._successors[vertex].append(successor)
                self._predecessors.setdefault(successor, []).append(vertex)
                if successor not in seen:
                    seen.add(successor)
                    self._successors.setdefault(successor, [])
                    work.append(successor)

    def _register(self, function: Function) -> None:
        for node in function.nodes:
            self._nodes[_node_key(node)] = node

    def node(self, vertex: Vertex) -> Node:
        return self._nodes[vertex.node_key]

    def _step(self, vertex: Vertex) -> list[Vertex]:
        node = self.node(vertex)
        entered = self._transfer(node, vertex.stack, vertex.resume)
        if entered is not None:
            target, returns_to, counts = entered
            self._register(target.function)
            frame = Frame(vertex.node_key, _function_key(target.function), returns_to, counts)
            return [Vertex(_node_key(target), vertex.stack + (frame,))]
        if node.sons:
            return [Vertex(_node_key(son), vertex.stack) for son in node.sons]
        return self._leave(vertex)

    def _transfer(
        self, node: Node, stack: tuple[Frame, ...], resume: int
    ) -> Optional[tuple[Node, Optional[tuple[tuple[str, int], int]], bool]]:
        """Interprocedural transfer at this node: (target, return site, counts towards d).

        `resume` is the IR index the node is entered at, so that the second call of a chain is found
        once the node is re-entered after the first returned.
        """
        if node.type == NodeType.PLACEHOLDER:
            # `_` continues at whatever followed the modifier marker node we came from.
            site = self._nodes.get(stack[-1].site_key) if stack else None
            if site is None or not site.sons:
                return None
            return (site.sons[0], (_node_key(node.sons[0]), 0) if node.sons else None, False)
        found = next_inlined_call(node, resume)
        if found is None:
            return None
        index, callee = found
        if _function_key(callee) in {frame.callee_key for frame in stack}:
            return None  # recursion: keep the ordinary edge, do not unroll
        if isinstance(callee, Modifier):
            # The function body is reached through the placeholder, so the marker node has no
            # return site of its own.
            return (callee.entry_point, None, False)
        # A normal call returns into this same node, just after the call, so a following chained call
        # is reached next; once no call remains, `_transfer` returns None and the node's sons follow.
        return (callee.entry_point, (_node_key(node), index + 1), True)

    def _leave(self, vertex: Vertex) -> list[Vertex]:
        """At an exit node pop frames until one supplies a return site."""
        stack = vertex.stack
        while stack:
            frame = stack[-1]
            stack = stack[:-1]
            if frame.returns_to is not None:
                node_key, resume = frame.returns_to
                return [Vertex(node_key, stack, resume)]
        return []

    # ----------------------------------------------------------------- queries

    def __len__(self) -> int:
        return len(self._successors)

    def vertices(self) -> Iterator[Vertex]:
        return iter(self._successors)

    def successors(self, vertex: Vertex) -> list[Vertex]:
        return self._successors.get(vertex, [])

    def predecessors(self, vertex: Vertex) -> list[Vertex]:
        return self._predecessors.get(vertex, [])

    def vertices_of(self, node: Node) -> list[Vertex]:
        """All occurrences of a Slither node in this expansion (one per call context)."""
        key = _node_key(node)
        return [vertex for vertex in self._successors if vertex.node_key == key]

    def reaches(self, node: Node) -> bool:
        return bool(self.vertices_of(node))

    def backward_reachable(self, target: Vertex) -> set[Vertex]:
        """N*_t: the vertices from which the target is reachable (2.19)."""
        seen = {target}
        work = deque([target])
        while work:
            current = work.popleft()
            for parent in self.predecessors(current):
                if parent not in seen:
                    seen.add(parent)
                    work.append(parent)
        return seen

    def branch_count(self, target: Vertex) -> int:
        """b(t): branching nodes inside N*_t, excluding the target itself."""
        return sum(
            1
            for vertex in self.backward_reachable(target)
            if vertex != target and is_branching(self.node(vertex))
        )

    def dominators(self, target: Vertex) -> set[Vertex]:
        """Vertices present on every path from the entry point to the target."""
        reachable = self.backward_reachable(target)
        result: set[Vertex] = set()
        for candidate in reachable:
            if candidate in (target, self.root):
                continue
            if not self._reaches_without(target, candidate):
                result.add(candidate)
        return result

    def _reaches_without(self, target: Vertex, blocked: Vertex) -> bool:
        """True if the target is still reachable from the root when `blocked` is removed."""
        seen = {self.root}
        work = deque([self.root])
        while work:
            current = work.popleft()
            if current == target:
                return True
            for successor in self.successors(current):
                if successor == blocked or successor in seen:
                    continue
                seen.add(successor)
                work.append(successor)
        return False

    def distances_to(self, target: Vertex) -> dict[Vertex, int]:
        """Shortest distance from each vertex to the target; used by the worklist order."""
        distances = {target: 0}
        work = deque([target])
        while work:
            current = work.popleft()
            for parent in self.predecessors(current):
                if parent not in distances:
                    distances[parent] = distances[current] + 1
                    work.append(parent)
        return distances


def entry_points(contract: Contract) -> list[Function]:
    """F_pub: public and external functions, including inherited ones, fallback and receive.

    Constructors are excluded: a write performed once at deployment cannot be triggered by an
    attacker, and `owner = msg.sender` would otherwise make every contract a confirmed SC01.
    """
    functions = [
        f
        for f in contract.functions
        if f.is_implemented and not f.is_constructor and f.visibility in ("public", "external")
    ]
    return sorted(functions, key=_function_key)


def expansions(contract: Contract) -> dict[str, Expansion]:
    """One expansion per entry point, in a stable order."""
    return {_function_key(f): Expansion(f) for f in entry_points(contract)}
