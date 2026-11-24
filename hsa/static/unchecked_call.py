"""SC06: unchecked low-level call.

phi_UC (2.7) is lcall_i(a, r_i) AND r_i = false AND write_j(v), j > i. As for RE the target is
the state write, not the call, so that the write stays inside N*_t.

"Low-level" means a call that reports failure through a return value instead of reverting:
`call`, `delegatecall`, `staticcall` and `send`. `transfer` reverts on failure and is therefore
never a UC candidate.

The success flag is considered CHECKED when it is read, directly or through a chain of copies,
by a node that branches -- `require(ok)`, `if (!ok) revert()`, `assert(ok)`. Whether the false
branch actually reaches the write is decided by the symbolic stage.
"""

from __future__ import annotations

from typing import Iterable, Optional

from slither.core.cfg.node import Node
from slither.core.declarations import Function
from slither.slithir.operations import (
    Assignment,
    LowLevelCall,
    Operation,
    Send,
    TypeConversion,
    Unary,
    Unpack,
)

from hsa.config import VulnClass
from hsa.icfg import Expansion, Vertex, is_branching
from hsa.model import Target
from hsa.static.base import (
    Analysis,
    build_target,
    state_writes_after,
    write_index,
)


def _low_level_calls(node: Node) -> list[Operation]:
    return [ir for ir in node.irs if isinstance(ir, (LowLevelCall, Send))]


def _success_flag(ir: Operation, node: Node) -> Optional[object]:
    """The variable holding the success of the call, or None when it is discarded.

    `to.call("")` as a statement produces no Unpack at all: the flag is dropped, which is the
    unchecked case by construction.
    """
    if isinstance(ir, Send):
        return ir.lvalue
    for other in node.irs:
        if isinstance(other, Unpack) and other.tuple is ir.lvalue and other.index == 0:
            return other.lvalue
    return None


class CheckedFlags:
    """Variables whose value reaches a branching condition, computed backwards in one function."""

    def __init__(self, function: Function) -> None:
        self._checked: set[object] = set()
        for node in function.nodes:
            if is_branching(node):
                self._checked.update(node.variables_read)
        self._saturate(function)

    def _saturate(self, function: Function) -> None:
        changed = True
        while changed:
            changed = False
            for node in function.nodes:
                for ir in node.irs:
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is None or lvalue not in self._checked:
                        continue
                    for source in _copies(ir):
                        if source is not None and source not in self._checked:
                            self._checked.add(source)
                            changed = True

    def is_checked(self, variable: Optional[object]) -> bool:
        return variable is not None and variable in self._checked


def _copies(ir: Operation) -> Iterable[object]:
    """Operations that merely move a boolean around."""
    if isinstance(ir, Assignment):
        return [ir.rvalue]
    if isinstance(ir, (TypeConversion, Unary, Unpack)):
        return list(ir.read)
    return []


class UncheckedCallDetector:
    """One target per state write that follows a low-level call with a discarded result."""

    vuln_class = VulnClass.UC

    def detect(self, analysis: Analysis) -> list[Target]:
        flags: dict[str, CheckedFlags] = {}
        targets: list[Target] = []
        for expansion in analysis.expansions.values():
            seen: set[Vertex] = set()
            for call in sorted(expansion.vertices(), key=lambda v: (v.node_key, len(v.stack))):
                node = expansion.node(call)
                key = node.function.canonical_name
                for ir in _low_level_calls(node):
                    if key not in flags:
                        flags[key] = CheckedFlags(node.function)
                    if flags[key].is_checked(_success_flag(ir, node)):
                        continue
                    targets.extend(self._from_call(analysis, expansion, call, node, ir, seen))
        return targets

    def _from_call(
        self,
        analysis: Analysis,
        expansion: Expansion,
        call: Vertex,
        call_node: Node,
        ir: Operation,
        seen: set[Vertex],
    ) -> list[Target]:
        targets = []
        for vertex, written in state_writes_after(expansion, call):
            if vertex in seen:
                continue
            seen.add(vertex)
            node = expansion.node(vertex)
            targets.append(
                build_target(
                    analysis,
                    expansion,
                    vertex,
                    VulnClass.UC,
                    # E_t = {call address, call arguments}
                    key_expressions=[ir.destination, *ir.arguments],
                    op_index=write_index(node, written[0]),
                    call_node=call_node,
                    key_node=call_node,
                )
            )
        return targets
