"""SC01: access control (2.8) and tx.origin authentication (2.9).

Both predicates are about the same set of privileged operations, so one detector produces both
kinds of target. For these classes the target IS the operation.

Priv, as defined in chapter 2:

* a write to a state variable of V_auth -- a variable compared with msg.sender somewhere;
* `selfdestruct` (and its old spelling `suicide`);
* a write to the implementation address of a proxy, recognised as a state variable that is used
  as the destination of a delegatecall.

An unprotected ether transfer (SWC-105) is deliberately NOT Priv and is outside the method.

phi_AC needs nothing beyond reaching the operation: the attacker model fixes sender = a* with
a* different from every V_auth value and from every address literal, so a reachable Priv is a
confirmed access-control flaw. phi_TO additionally needs a path condition that reads tx.origin
without reading msg.sender -- a tx.origin check does not restrict a*, it only restricts who
initiated the transaction.
"""

from __future__ import annotations

from typing import Iterable

from slither.core.cfg.node import Node
from slither.core.declarations import SolidityVariableComposed
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Assignment, Index, Member, Operation, SolidityCall

from hsa.config import VulnClass
from hsa.icfg import Expansion, Vertex, is_branching
from hsa.model import Target
from hsa.static.base import (
    DESTRUCT_SIGNATURES,
    SENDER,
    Analysis,
    build_target,
    resolve_state_variable,
)

_ORIGIN = str(SolidityVariableComposed("tx.origin"))


def _privileged(node: Node, auth: set[StateVariable], proxy: set[StateVariable]) -> list[int]:
    """Indices of the privileged operations of this node."""
    found = []
    for index, ir in enumerate(node.irs):
        if isinstance(ir, SolidityCall) and ir.function.full_name in DESTRUCT_SIGNATURES:
            found.append(index)
            continue
        if isinstance(ir, (Index, Member)):
            continue  # these build a reference, they do not write through it
        lvalue = getattr(ir, "lvalue", None)
        if lvalue is None:
            continue
        written = resolve_state_variable(lvalue, node)
        if written is not None and (written in auth or written in proxy):
            found.append(index)
    return found


def _operands(ir: Operation) -> list[object]:
    """The operands of the privileged operation itself: the new value, or the recipient."""
    if isinstance(ir, SolidityCall):
        return list(ir.arguments)
    if isinstance(ir, Assignment):
        return [ir.rvalue]
    return list(ir.read)


def _origin_only_condition(node: Node) -> bool:
    """A branching node that reads tx.origin and does not read msg.sender."""
    if not is_branching(node):
        return False
    names = {str(v) for v in node.variables_read}
    return _ORIGIN in names and str(SENDER) not in names


class AccessControlDetector:
    """Produces an AC target for every privileged operation, plus a TO target where applicable."""

    vuln_class = VulnClass.AC

    def detect(self, analysis: Analysis) -> list[Target]:
        proxy = analysis.proxy_variables
        targets: list[Target] = []
        for expansion in analysis.expansions.values():
            for vertex in sorted(expansion.vertices(), key=lambda v: (v.node_key, len(v.stack))):
                node = expansion.node(vertex)
                for index in _privileged(node, analysis.auth, proxy):
                    targets.extend(
                        self._from_operation(analysis, expansion, vertex, node, index)
                    )
        return targets

    def _from_operation(
        self,
        analysis: Analysis,
        expansion: Expansion,
        vertex: Vertex,
        node: Node,
        index: int,
    ) -> Iterable[Target]:
        # E_t = {sender, operands of the privileged operation}
        yield build_target(
            analysis,
            expansion,
            vertex,
            VulnClass.AC,
            key_expressions=[SENDER, *_operands(node.irs[index])],
            op_index=index,
        )
        if not self._has_origin_check(expansion, vertex):
            return
        # E_t = {sender, origin}: both are in X_env, so A is 1 for every TO target.
        yield build_target(
            analysis,
            expansion,
            vertex,
            VulnClass.TO,
            key_expressions=[SENDER, SolidityVariableComposed("tx.origin")],
            op_index=index,
        )

    def _has_origin_check(self, expansion: Expansion, target: Vertex) -> bool:
        """Over-approximation of "exists c in PC": any condition that can precede the target."""
        return any(
            _origin_only_condition(expansion.node(v))
            for v in expansion.backward_reachable(target)
            if v != target
        )
