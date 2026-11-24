"""SC08: one-level re-entry model (phi_RE, 2.6).

The RE target is the state WRITE that follows an external call. The engine reaches it on a path
whose trace already holds the call event, and each call event carries the snapshot Sigma_i of the
state at the moment of the call (translator). `check_reentrancy` turns that into a verdict.

phi_RE (2.6):

    call_i(a) AND Ctrl(a) AND v read before i AND write_j(v), j > i
      AND exists g in F_pub: Sat(PC_g(Sigma_i)) AND g accesses v.

The static stage has already guaranteed "v read before i" and "write_j(v), j > i": the target IS
that write, produced only when a variable read before the call is written after it. So here two
things are decided on the real symbolic state:

1. the current path reaches the write (PC sat) and the call address a is controlled (Ctrl(a));
2. some public function g is a *re-entry candidate* whose value action is reachable in Sigma_i.

A public function g is a re-entry candidate (the author's finalised criterion) if, on a reachable
path:

* an EXPLICIT condition (an `if` / `require` / `assert`) reads v -- the implicit 0.8 overflow
  check does not count, so an unguarded `balances[x] += v` in a plain `deposit` is not a candidate;
* AFTER that condition g performs a value action: it transfers ether, performs a privileged
  operation, or writes a variable that stores value (the M(t) notion -- an ether transfer or a
  `mapping(address => uint)` write).

"After that condition" is read as domination: the value-action node must be dominated by a
condition that reads v, so every path reaching it passes the condition. This is the safe direction
(it only drops candidates). The condition is then checked dynamically: g is run from Sigma_i with

* storage = the storage at the call moment (Sigma_i.mu: writes before the call counted, after not);
* PC = Sigma_i.PC, so the storage satisfies whatever made the outer call reachable;
* sender_g = a, the called contract that re-enters, so `msg.sender` inside g is the attacker;
* origin_g = the same tx.origin, value_g and the arguments of g fresh.

A dominating `require(!locked)` with `locked = true` already in Sigma_i.mu is then unsat, which is
exactly why `nonReentrant` on the re-entered function gives REFUTED, while a `transfer` left
unprotected (cross-function re-entry, the classic DAO shape) stays reachable and gives CONFIRMED.
"""

from __future__ import annotations

from typing import Iterable, Optional

import z3
from slither.core.cfg.node import Node
from slither.core.declarations import Function
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Index, Member
from slither.slithir.variables import Constant, ReferenceVariable

from hsa.config import VulnClass
from hsa.icfg import Expansion, Vertex, is_branching
from hsa.model import Context, EventKind, ProgramPoint, SymState, Target, UnknownReason, Verdict
from hsa.static.base import (
    _is_address_to_uint,
    _transfers_ether,
    resolve_state_variable,
)
from hsa.symexec.predicates import (
    Outcome,
    Probe,
    _budget_ms,
    _counterexample,
    _is_controlled,
    _solve,
)
from hsa.symexec.state import (
    ADDRESS_BITS,
    BYTES,
    DATA,
    ORIGIN,
    SENDER,
    VALUE,
    WORD_BITS,
    Environment,
    Machine,
    environment_constraints,
    sort_of,
)

if False:  # pragma: no cover - typing only, avoids a static import cycle
    from hsa.static.base import Analysis


# ----------------------------------------------------------------------------- phi_RE


def check_reentrancy(
    probe: Probe, state: SymState, target: Target, node: Node, analysis: "Analysis"
) -> Outcome:
    """phi_RE (2.6) on the state positioned just before the write that is the target."""
    written = set(node.state_variables_written)
    if not written:
        return Outcome(Verdict.REFUTED)

    events = [
        event
        for event in state.tau
        if event.kind in (EventKind.CALL, EventKind.LCALL, EventKind.DCALL)
        and event.can_reenter
        and event.snapshot is not None
        and event.destination is not None
        and _is_controlled(probe, event.destination)
    ]
    if not events:
        return Outcome(Verdict.REFUTED)  # no controllable re-entrant call precedes the write

    status, model = _solve([*state.pc], _budget_ms(probe.budget))
    if status == z3.unsat:
        return Outcome(Verdict.REFUTED)  # the write is not reached on this path at all
    if status != z3.sat:
        return Outcome(Verdict.UNKNOWN, UnknownReason.SOLVER_UNKNOWN)

    candidates = _reentry_candidates(analysis, probe.config, written)
    unknown = False
    for event in events:
        for expansion, vertex in candidates:
            outcome = _reachable_in_snapshot(probe, analysis, expansion, vertex, event)
            if outcome.verdict is Verdict.CONFIRMED:
                witness = _counterexample(probe, state, model)
                witness.reentry_function = expansion.entry_point.canonical_name
                return Outcome(Verdict.CONFIRMED, counterexample=witness)
            if outcome.verdict is Verdict.UNKNOWN:
                unknown = True
    if unknown:
        return Outcome(Verdict.UNKNOWN, UnknownReason.SOLVER_UNKNOWN)
    return Outcome(Verdict.REFUTED)


# ------------------------------------------------------------------ candidate detection


def _reentry_candidates(
    analysis: "Analysis", config, written: set[StateVariable]
) -> list[tuple[Expansion, Vertex]]:
    """Public functions with a value-action node dominated by an explicit condition reading v.

    Returned as (expansion, value-action vertex) pairs so the caller can run a directed reachability
    search to the vertex in Sigma_i. A pair is kept only once per node.
    """
    pairs: list[tuple[Expansion, Vertex]] = []
    for expansion in analysis.expansions.values():
        taints: dict[str, _StateVarTaint] = {}
        seen: set[Vertex] = set()
        for vertex in sorted(expansion.vertices(), key=lambda v: (v.node_key, len(v.stack))):
            if vertex in seen or vertex.depth > config.d_inline:
                continue
            node = expansion.node(vertex)
            if not _is_value_action(node, analysis):
                continue
            if _dominated_by_condition_on_v(expansion, vertex, written, taints):
                seen.add(vertex)
                pairs.append((expansion, vertex))
    return pairs


def _is_value_action(node: Node, analysis: "Analysis") -> bool:
    """A node that moves value: ether transfer, mapping(address => uint) write, or a privileged op."""
    if _transfers_ether(node):
        return True
    written = node.state_variables_written
    if any(_is_address_to_uint(variable) for variable in written):
        return True
    return any(variable in analysis.auth or variable in analysis.proxy_variables for variable in written)


def _dominated_by_condition_on_v(
    expansion: Expansion,
    vertex: Vertex,
    written: set[StateVariable],
    taints: dict[str, "_StateVarTaint"],
) -> bool:
    """Some dominator of `vertex` is an explicit condition whose value depends on a variable in v."""
    for dominator in expansion.dominators(vertex):
        node = expansion.node(dominator)
        if is_branching(node) and _conditions_on(node, written, taints):
            return True
    return False


def _conditions_on(
    node: Node, written: set[StateVariable], taints: dict[str, "_StateVarTaint"]
) -> bool:
    """Does this branching node's condition read a variable in `written` (transitively)?"""
    for variable in node.state_variables_read:
        if variable in written:
            return True
    taint = taints.get(node.function.canonical_name)
    if taint is None:
        taint = _StateVarTaint(node.function, written)
        taints[node.function.canonical_name] = taint
    return taint.reads_v(node)


class _StateVarTaint:
    """Locals and references in one function whose value derives from reading a state variable in v.

    A forward value-dependency, seeded from reads of v and propagated like `ValueTaint`, so that
    `require(amount > 0)` with `amount = balances[sender]` counts as a condition on `balances`.
    """

    def __init__(self, function: Function, variables: set[StateVariable]) -> None:
        self._variables = variables
        self._tainted: set[object] = set()
        self._saturate(function)

    def _saturate(self, function: Function) -> None:
        changed = True
        while changed:
            changed = False
            for node in function.nodes:
                for ir in node.irs:
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is None:
                        continue
                    if isinstance(lvalue, ReferenceVariable) and not isinstance(ir, (Index, Member)):
                        continue  # a reference's provenance is fixed by its Index / Member
                    if any(self._is_source(s, node) for s in ir.read) and lvalue not in self._tainted:
                        self._tainted.add(lvalue)
                        changed = True

    def _is_source(self, variable: object, node: Node) -> bool:
        if variable is None or isinstance(variable, Constant):
            return False
        if variable in self._tainted or variable in self._variables:
            return True
        return resolve_state_variable(variable, node) in self._variables

    def reads_v(self, node: Node) -> bool:
        return any(self._is_source(variable, node) for variable in node.variables_read)


# --------------------------------------------------------- reachability in the snapshot


def _reachable_in_snapshot(
    probe: Probe, analysis: "Analysis", expansion: Expansion, vertex: Vertex, event
) -> Outcome:
    """Is the value-action node reachable when the re-entered function g runs from Sigma_i?"""
    from hsa.symexec.engine import _search  # local: engine imports this module

    machine: Machine = probe.machine
    g = expansion.entry_point
    snapshot = event.snapshot

    environment = Environment(
        sender=event.destination,  # a: the called contract re-enters, so msg.sender is the attacker
        origin=snapshot.env.get(ORIGIN, machine.fresh(ORIGIN, z3.BitVecSort(ADDRESS_BITS))),
        value=machine.fresh(VALUE, z3.BitVecSort(WORD_BITS)),
        data=machine.fresh(DATA, BYTES),
    )
    state = SymState()
    state.mu = dict(snapshot.mu)  # storage at the call moment
    for parameter in g.parameters:
        state.rho[parameter.name] = machine.fresh(parameter.name, sort_of(parameter.type))
    state.env.update(environment.terms())
    state.pc = list(snapshot.pc) + environment_constraints(environment)

    controlled = tuple(environment.terms().values()) + tuple(
        state.rho[p.name] for p in g.parameters if p.name in state.rho
    )
    nstar = expansion.backward_reachable(vertex)
    distances = dict(expansion.distances_to(vertex))
    synthetic = Target(
        point=ProgramPoint(function=expansion.node(vertex).function, node=expansion.node(vertex), op_index=0),
        context=Context(vuln_class=VulnClass.RE, entry_point=g),
    )
    return _search(
        machine,
        environment,
        controlled,
        analysis,
        synthetic,
        probe.config,
        probe.budget,
        expansion,
        {vertex},
        nstar,
        distances,
        state,
        reach_only=True,
    )
