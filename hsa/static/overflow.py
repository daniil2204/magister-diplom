"""SC09: integer overflow and underflow.

Static rule (refinement of table 2.3). An arithmetic operation becomes a target only if all of
the following hold:

1. it is evaluated in an unchecked context -- below Solidity 0.8 that is all arithmetic, from
   0.8 on only the inside of an `unchecked` block;
2. at least one operand depends BY VALUE on X_env or X_arg;
3. the result reaches a sink: a storage write, a transfer amount, a call argument, or a
   condition.

Condition 3 is what keeps OV from flooding the queue on old contracts: without it every
intermediate expression of a pre-0.8 token contract would become a target.
"""

from __future__ import annotations

from typing import Iterable

from slither.core.cfg.node import Node
from slither.core.declarations import Function
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    HighLevelCall,
    Index,
    InternalCall,
    LowLevelCall,
    Member,
    Operation,
    Send,
    SolidityCall,
    Transfer,
    TypeConversion,
    Unary,
)
from slither.slithir.variables import ReferenceVariable

from hsa.config import VulnClass
from hsa.icfg import is_branching
from hsa.model import Target
from hsa.static.base import Analysis, build_target, resolve_state_variable

#: Operations that can wrap. Division and modulo cannot overflow for unsigned operands, and
#: the method does not model the single signed edge case (type(int).min / -1).
ARITHMETIC = frozenset(
    {BinaryType.ADDITION, BinaryType.SUBTRACTION, BinaryType.MULTIPLICATION}
)


class SinkAnalysis:
    """Variables whose value reaches a sink, computed backwards inside one function."""

    def __init__(self, function: Function) -> None:
        self._reaching: set[object] = set()
        self._seed(function)
        self._saturate(function)

    def _seed(self, function: Function) -> None:
        for node in function.nodes:
            if is_branching(node):
                self._reaching.update(node.variables_read)
            for ir in node.irs:
                self._reaching.update(_sink_operands(ir, node))

    def _saturate(self, function: Function) -> None:
        changed = True
        while changed:
            changed = False
            for node in function.nodes:
                for ir in node.irs:
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is None or lvalue not in self._reaching:
                        continue
                    for source in _value_sources(ir):
                        if source is not None and source not in self._reaching:
                            self._reaching.add(source)
                            changed = True

    def reaches_sink(self, variable: object) -> bool:
        return variable in self._reaching


def _sink_operands(ir: Operation, node: Node) -> Iterable[object]:
    """Operands of this operation that are consumed by a sink."""
    if isinstance(ir, (Transfer, Send)):
        return [ir.call_value]
    if isinstance(ir, (LowLevelCall, HighLevelCall)):
        return [ir.call_value, *ir.arguments]
    if isinstance(ir, InternalCall):
        return list(ir.arguments)
    if isinstance(ir, SolidityCall):
        return list(ir.read)
    if isinstance(ir, (Assignment, Binary)) and _writes_storage(ir, node):
        return list(ir.read)
    return []


def _writes_storage(ir: Operation, node: Node) -> bool:
    lvalue = getattr(ir, "lvalue", None)
    if lvalue is None:
        return False
    return resolve_state_variable(lvalue, node) is not None


def _value_sources(ir: Operation) -> Iterable[object]:
    if isinstance(ir, (Index, Member)):
        return [ir.variable_left]
    if isinstance(ir, Binary):
        return [ir.variable_left, ir.variable_right]
    if isinstance(ir, Assignment):
        return [ir.rvalue]
    if isinstance(ir, (TypeConversion, Unary)):
        return list(ir.read)
    return list(ir.read)


class OverflowDetector:
    """Produces one target per unchecked arithmetic operation that can reach a sink."""

    vuln_class = VulnClass.OV

    def detect(self, analysis: Analysis) -> list[Target]:
        sinks: dict[str, SinkAnalysis] = {}
        targets: list[Target] = []
        for expansion in analysis.expansions.values():
            for vertex in expansion.vertices():
                node = expansion.node(vertex)
                if not self._is_unchecked(analysis, node):
                    continue
                key = node.function.canonical_name
                if key not in sinks:
                    sinks[key] = SinkAnalysis(node.function)
                for index, ir in enumerate(node.irs):
                    if not isinstance(ir, Binary) or ir.type not in ARITHMETIC:
                        continue
                    operands = [ir.variable_left, ir.variable_right]
                    if not any(analysis.is_controlled(o, node) for o in operands):
                        continue
                    if not self._reaches_sink(ir, node, sinks[key]):
                        continue
                    targets.append(
                        build_target(
                            analysis,
                            expansion,
                            vertex,
                            VulnClass.OV,
                            key_expressions=operands,  # E_t = {x, y}
                            op_index=index,
                        )
                    )
        return targets

    def _is_unchecked(self, analysis: Analysis, node: Node) -> bool:
        """Below 0.8 every operation is unchecked; from 0.8 only inside an `unchecked` block."""
        if not analysis.compilation.checked_arithmetic:
            return True
        return not node.scope.is_checked

    def _reaches_sink(self, ir: Binary, node: Node, sinks: SinkAnalysis) -> bool:
        if _writes_storage(ir, node):
            return True
        lvalue = ir.lvalue
        if isinstance(lvalue, ReferenceVariable) and resolve_state_variable(lvalue, node):
            return True
        return sinks.reaches_sink(lvalue)
