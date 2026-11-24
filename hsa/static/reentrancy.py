"""SC08: reentrancy.

The target is the state WRITE that follows an external call, not the call itself. From the write
the call node is no longer reachable, so if the call were the target the write would lie outside
N*_t and the directed search would prune the very operation the predicate needs. The call node is
kept in the context; the symbolic state at the call is carried by the CALL event of the trace.

Static rule, the part of phi_RE (2.6) that is decidable without a solver:

1. a node performs an external call that can give control back -- `transfer` and `send` do not
   qualify, their 2300 gas stipend cannot pay for a state write;
2. a state variable v is read on some path up to the call;
3. v is written at a node reachable after the call;
4. v is not a lock variable.

Rule 4 is an exclusion, not an approximation: `locked = false` in the tail of `nonReentrant` is
read before the call and written after it, so it satisfies 1-3 exactly, yet it is the protection
mechanism rather than the vulnerability. "Lock variable" is the notion already defined for g(t),
so nothing new is introduced.

Ctrl(a) and the existence of a public re-entry function g are left to the symbolic stage: the
static stage over-approximates, and A(t) already reflects whether the call address is controlled.
"""

from __future__ import annotations

from slither.core.cfg.node import Node
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Operation

from hsa.config import VulnClass
from hsa.icfg import Expansion, Vertex
from hsa.model import Target
from hsa.static.base import (
    Analysis,
    build_target,
    lock_variables,
    reentrant_calls,
    state_reads_before,
    state_writes_after,
    write_index,
)


def _key_expressions(ir: Operation) -> list[object]:
    """E_t = {call address, value}."""
    return [ir.destination, getattr(ir, "call_value", None)]


class ReentrancyDetector:
    """One target per (external call, state write after it) pair that shares a variable."""

    vuln_class = VulnClass.RE

    def detect(self, analysis: Analysis) -> list[Target]:
        targets: list[Target] = []
        for expansion in analysis.expansions.values():
            seen: set[Vertex] = set()
            locks = lock_variables(expansion)
            for call in sorted(expansion.vertices(), key=lambda v: (v.node_key, len(v.stack))):
                node = expansion.node(call)
                for ir in reentrant_calls(node):
                    targets.extend(
                        self._from_call(analysis, expansion, call, node, ir, seen, locks)
                    )
        return targets

    def _from_call(
        self,
        analysis: Analysis,
        expansion: Expansion,
        call: Vertex,
        call_node: Node,
        ir: Operation,
        seen: set[Vertex],
        locks: set[StateVariable],
    ) -> list[Target]:
        read_before = state_reads_before(expansion, call) - locks
        if not read_before:
            return []
        targets = []
        for vertex, written in state_writes_after(expansion, call):
            if vertex in seen or not any(v in read_before for v in written):
                continue
            seen.add(vertex)
            node = expansion.node(vertex)
            relevant = next(v for v in written if v in read_before)
            targets.append(
                build_target(
                    analysis,
                    expansion,
                    vertex,
                    VulnClass.RE,
                    key_expressions=_key_expressions(ir),
                    op_index=write_index(node, relevant),
                    call_node=call_node,
                    key_node=call_node,
                )
            )
        return targets
