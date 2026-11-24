"""Shared primitives of the static stage.

Everything here is computed on the interprocedural graph of `hsa.icfg`, from the entry point:
the whole context of a target (E_t, G_t, g, M) is a property of the entry point, not of the
function that happens to contain the node.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Optional, Protocol

from slither.core.cfg.node import Node
from slither.core.declarations import (
    Contract,
    Function,
    SolidityVariable,
    SolidityVariableComposed,
)
from slither.core.solidity_types import ElementaryType, MappingType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    Call,
    HighLevelCall,
    Index,
    LowLevelCall,
    Member,
    Operation,
    Send,
    SolidityCall,
    Transfer,
    TypeConversion,
    Unary,
    Unpack,
)
from slither.slithir.variables import Constant, ReferenceVariable, TupleVariable

from hsa.config import VulnClass
from hsa.icfg import Expansion, Vertex, inlined_callee
from hsa.model import Context, ProgramPoint, Target
from hsa.prep import Compilation

#: X_env, the environment inputs of formula (2.3).
#:
#: `msg.data` belongs here even though it is not in the published form of (2.3): in a proxy the
#: forwarded calldata of `implementation.delegatecall(msg.data)` is entirely attacker-chosen, and
#: leaving it out would make the destination data of every real proxy look uncontrolled.
ENV_VARIABLES = frozenset({"msg.sender", "tx.origin", "msg.value", "msg.data"})

_EQUALITY = frozenset({BinaryType.EQUAL, BinaryType.NOT_EQUAL})


# --------------------------------------------------------------------- controllability


class ValueTaint:
    """Ctrl(e) approximated by value dependency inside one function (2.5).

    The index of a mapping does not make the value controllable: for `Select(m, k)` the value
    comes from `m`, that is from X_sto, while `k` only picks the cell. Without this rule
    `balances[msg.sender]` would be controllable and OV would flood the queue on pre-0.8 code.
    """

    def __init__(self, function: Function) -> None:
        self._tainted: set[object] = set()
        self._seed(function)
        self._saturate(function)

    def _seed(self, function: Function) -> None:
        self._tainted.update(function.parameters)  # X_arg

    def _saturate(self, function: Function) -> None:
        changed = True
        while changed:
            changed = False
            for node in function.nodes:
                for ir in node.irs:
                    for written in self._propagate(ir):
                        if written not in self._tainted:
                            self._tainted.add(written)
                            changed = True

    def _propagate(self, ir: Operation) -> Iterable[object]:
        """Yield the lvalue when the VALUE of the result depends on a controlled input."""
        lvalue = getattr(ir, "lvalue", None)
        if lvalue is None:
            return ()
        if isinstance(lvalue, ReferenceVariable) and not isinstance(ir, (Index, Member)):
            # A reference is an alias for a storage cell. Slither compiles `balances[x] -= v`
            # into `REF = REF - v`, reusing the same reference on both sides; propagating here
            # would let the result taint its own operand and make `balances[x]` controllable.
            # The provenance of a reference is fixed by the Index or Member that defined it.
            return ()
        if isinstance(ir, Index):
            # Only the base matters; the key merely selects a cell.
            sources: Iterable[object] = [ir.variable_left]
        elif isinstance(ir, Member):
            sources = [ir.variable_left]
        elif isinstance(ir, (Assignment, TypeConversion, Unary, Unpack)):
            sources = [ir.rvalue if isinstance(ir, Assignment) else _single_read(ir)]
        elif isinstance(ir, Binary):
            sources = [ir.variable_left, ir.variable_right]
        elif inlined_callee(ir) is not None:
            # An inlined call: an ordinary internal call, or an internal/private library function
            # such as classic SafeMath. The engine inlines these as an exact model, so the static
            # stage approximates them the same way -- the result depends on the arguments. A
            # public/external library call is a DELEGATECALL to unknown code, so `inlined_callee`
            # returns None and it falls through to the opaque branch below.
            sources = list(ir.arguments)
        elif isinstance(ir, (LowLevelCall, HighLevelCall, Transfer, Send, SolidityCall)):
            # The result of an external call is a fresh symbol, not an element of X_env or X_arg.
            return ()
        else:
            sources = list(ir.read)
        return [lvalue] if any(self.is_controlled(s) for s in sources) else ()

    def is_controlled(self, variable: object) -> bool:
        if variable is None or isinstance(variable, Constant):
            return False
        if isinstance(variable, SolidityVariable):
            return str(variable) in ENV_VARIABLES
        if isinstance(variable, StateVariable):
            return False  # X_sto is free, not attacker-controlled
        return variable in self._tainted


def _single_read(ir: Operation) -> Optional[object]:
    reads = list(ir.read)
    return reads[0] if reads else None


# ------------------------------------------------------------------- authorisation data


def resolve_state_variable(variable: object, node: Node) -> Optional[StateVariable]:
    """Follow Index / Member references back to the state variable they read."""
    if isinstance(variable, StateVariable):
        return variable
    if not isinstance(variable, ReferenceVariable):
        return None
    for ir in node.irs:
        if isinstance(ir, (Index, Member)) and ir.lvalue is variable:
            return resolve_state_variable(ir.variable_left, node)
    return None


def _sender_comparisons(node: Node) -> list[StateVariable]:
    """State variables compared with msg.sender in this node."""
    found = []
    for ir in node.irs:
        if not isinstance(ir, Binary) or ir.type not in _EQUALITY:
            continue
        operands = (ir.variable_left, ir.variable_right)
        if not any(str(o) == "msg.sender" for o in operands):
            continue
        for operand in operands:
            resolved = resolve_state_variable(operand, node)
            if resolved is not None:
                found.append(resolved)
    return found


def auth_variables(contract: Contract) -> set[StateVariable]:
    """V_auth: state variables compared with msg.sender in at least one function."""
    found: set[StateVariable] = set()
    for function in list(contract.functions) + list(contract.modifiers):
        for node in function.nodes:
            found.update(_sender_comparisons(node))
    return found


def address_constants(contract: Contract) -> set[int]:
    """K_addr: every address literal of the contract.

    Over-approximating here is safe: it only narrows the set of addresses the attacker may use.
    """
    found: set[int] = set()
    for function in list(contract.functions) + list(contract.modifiers):
        for node in function.nodes:
            for ir in node.irs:
                for operand in ir.read:
                    if isinstance(operand, Constant) and _is_address(operand):
                        found.add(int(operand.value))
    for variable in contract.state_variables:
        if isinstance(variable.type, ElementaryType) and variable.type.name == "address":
            if isinstance(variable.expression, Constant):
                found.add(int(variable.expression.value))
    return found


def _is_address(constant: Constant) -> bool:
    return isinstance(constant.type, ElementaryType) and constant.type.name == "address"


# ---------------------------------------------------------------------------- calls

#: `callcode` is the pre-0.5 spelling of `delegatecall` and shares its semantics.
DELEGATECALL_NAMES = frozenset({"delegatecall", "callcode"})

#: `suicide` is the pre-0.5 spelling of `selfdestruct`.
DESTRUCT_SIGNATURES = frozenset({"selfdestruct(address)", "suicide(address)"})

SENDER = SolidityVariableComposed("msg.sender")


def is_delegatecall(ir: Operation) -> bool:
    return isinstance(ir, LowLevelCall) and str(ir.function_name) in DELEGATECALL_NAMES


def delegatecall_destinations(contract: Contract) -> set[StateVariable]:
    """State variables used as the destination of a delegatecall.

    Writing one of them is the "proxy implementation address" case of Priv. It is detected from
    the code rather than from a name list, so `masterCopy` or `_impl` are covered too.
    """
    found: set[StateVariable] = set()
    for function in list(contract.functions) + list(contract.modifiers):
        for node in function.nodes:
            for ir in node.irs:
                if not is_delegatecall(ir):
                    continue
                resolved = resolve_state_variable(ir.destination, node)
                if resolved is not None:
                    found.add(resolved)
    return found


def reentrant_calls(node: Node) -> list[Operation]:
    """External calls at this node that can give control back to the callee.

    `can_reenter` is Slither's own judgement: it excludes `staticcall`, and `transfer` / `send`
    inherit the default False because the 2300 gas stipend cannot pay for a state write.
    """
    return [ir for ir in node.irs if isinstance(ir, Call) and ir.can_reenter()]


def write_index(node: Node, variable: StateVariable) -> int:
    """Index in `node.irs` of the operation that writes the state variable.

    Index and Member only create the reference; the write is the operation that assigns through
    it, so they are skipped.
    """
    for index, ir in enumerate(node.irs):
        if isinstance(ir, (Index, Member)):
            continue
        lvalue = getattr(ir, "lvalue", None)
        if lvalue is not None and resolve_state_variable(lvalue, node) is variable:
            return index
    return 0


def state_writes_after(
    expansion: Expansion, call: Vertex
) -> list[tuple[Vertex, list[StateVariable]]]:
    """Vertices strictly after the call that write a state variable, in a stable order.

    "After" is forward reachability on the expansion, so the tail of a modifier -- which runs
    after the body and therefore after a call inside it -- is included.
    """
    seen = {call}
    work = deque(expansion.successors(call))
    reached: set[Vertex] = set()
    while work:
        current = work.popleft()
        if current in seen:
            continue
        seen.add(current)
        reached.add(current)
        work.extend(expansion.successors(current))
    found = []
    for vertex in sorted(reached, key=lambda v: (v.node_key, len(v.stack))):
        written = sorted(expansion.node(vertex).state_variables_written, key=str)
        if written:
            found.append((vertex, written))
    return found


def state_reads_before(expansion: Expansion, call: Vertex) -> set[StateVariable]:
    """State variables read on some path from the entry point up to and including the call."""
    found: set[StateVariable] = set()
    for vertex in expansion.backward_reachable(call):
        found.update(expansion.node(vertex).state_variables_read)
    return found


# ------------------------------------------------------------------------------ M(t)


def _is_address_to_uint(variable: StateVariable) -> bool:
    kind = variable.type
    if not isinstance(kind, MappingType):
        return False
    key, value = kind.type_from, kind.type_to
    return (
        isinstance(key, ElementaryType)
        and key.name == "address"
        and isinstance(value, ElementaryType)
        and value.name.startswith("uint")
    )


def _transfers_ether(node: Node) -> bool:
    """Any operation that moves ether out of the contract.

    `selfdestruct` counts: it forwards the entire remaining balance, which is a movement of value
    in exactly the sense M_t is about, even though it is not a call.
    """
    for ir in node.irs:
        if isinstance(ir, (Transfer, Send)):
            return True
        if isinstance(ir, (LowLevelCall, HighLevelCall)) and ir.call_value is not None:
            return True
        if isinstance(ir, SolidityCall) and ir.function.full_name in DESTRUCT_SIGNATURES:
            return True
    return False


def moves_value(expansion: Expansion) -> bool:
    """M_t: does the ENTRY POINT move ether or change a mapping(address => uint)?

    Computed over the whole expansion -- modifiers and internal calls at any depth -- because
    M_t describes the context of the target, not the prefix of the path leading to it.
    """
    for vertex in expansion.vertices():
        node = expansion.node(vertex)
        if _transfers_ether(node):
            return True
        if any(_is_address_to_uint(v) for v in node.state_variables_written):
            return True
    return False


# ------------------------------------------------------------------------------ g(t)


def _reads_scalar_state(node: Node) -> set[StateVariable]:
    return {
        v
        for v in node.state_variables_read
        if isinstance(v.type, ElementaryType)
    }


def _assigns_constant(node: Node, variable: StateVariable) -> bool:
    for ir in node.irs:
        if isinstance(ir, Assignment) and ir.lvalue is variable and isinstance(ir.rvalue, Constant):
            return True
    return False


def forward_reachable(expansion: Expansion, start: Vertex) -> set[Vertex]:
    """Vertices reachable from `start`, including `start` itself."""
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for successor in expansion.successors(current):
            if successor not in seen:
                seen.add(successor)
                stack.append(successor)
    return seen


def lock_variables(expansion: Expansion) -> set[StateVariable]:
    """Scalar state variables used as a re-entrancy lock, as defined for g(t).

    A lock is read in a branching condition and assigned a CONSTANT somewhere after it. The
    definition is reused verbatim from D(t) so that no second notion of "lock" enters the method.

    These are collected so that SC08 can skip them: `locked = false` in the tail of a modifier is
    read before the call and written after it, so it matches the static rule for SC08 exactly --
    but it is the protection mechanism, not the vulnerability. Without the exclusion every
    `nonReentrant` would add one spurious target per function, and a target the symbolic stage
    did not reach in time would count as a false positive in moderate mode.
    """
    found: set[StateVariable] = set()
    for vertex in expansion.vertices():
        node = expansion.node(vertex)
        if not _is_condition(node):
            continue
        after = forward_reachable(expansion, vertex) - {vertex}
        for variable in _reads_scalar_state(node) - found:
            if any(_assigns_constant(expansion.node(v), variable) for v in after):
                found.add(variable)
    return found


class GuardCounter:
    """g(t): dominating guards that restrict WHO can reach the target.

    Two kinds count, per the definition of D(t):

    * a comparison of msg.sender with a V_auth variable;
    * a lock variable -- a SCALAR state variable read in a dominating condition and assigned a
      CONSTANT on the path between that condition and the target.

    Conditions on amounts do not count: `require(amount > 0)` restricts the value, not the
    caller. That is also what separates g(t) from b(t).
    """

    def __init__(self, expansion: Expansion, auth: set[StateVariable]) -> None:
        self._expansion = expansion
        self._auth = auth

    def count(self, target: Vertex) -> tuple[int, list[Node]]:
        """Return g(t) and G_t, the dominating guard nodes."""
        dominators = self._expansion.dominators(target)
        between = self._expansion.backward_reachable(target)
        guards = [
            self._expansion.node(v)
            for v in sorted(dominators, key=lambda v: (v.node_key, len(v.stack)))
            if self._is_guard(v, between)
        ]
        return (len(guards), guards)

    def _is_guard(self, vertex: Vertex, between: set[Vertex]) -> bool:
        node = self._expansion.node(vertex)
        if not _is_condition(node):
            return False
        if any(v in self._auth for v in _sender_comparisons(node)):
            return True
        return any(self._is_lock(vertex, v, between) for v in _reads_scalar_state(node))

    def _is_lock(self, condition: Vertex, variable: StateVariable, between: set[Vertex]) -> bool:
        """The variable must be set to a constant between the condition and the target."""
        reachable = forward_reachable(self._expansion, condition)
        return any(
            _assigns_constant(self._expansion.node(v), variable)
            for v in reachable & between
            if v != condition
        )


def _is_condition(node: Node) -> bool:
    from hsa.icfg import is_branching

    return is_branching(node)


# -------------------------------------------------------------------- detector plumbing


@dataclass
class Analysis:
    """Everything a detector needs about one contract."""

    compilation: Compilation
    contract: Contract
    expansions: dict[str, Expansion]
    auth: set[StateVariable] = field(default_factory=set)  # V_auth
    address_literals: set[int] = field(default_factory=set)  # K_addr
    #: State variables holding a proxy implementation address; writing them is Priv.
    proxy_variables: set[StateVariable] = field(default_factory=set)
    _taint: dict[str, ValueTaint] = field(default_factory=dict, repr=False)

    @classmethod
    def build(cls, compilation: Compilation, contract: Contract) -> "Analysis":
        from hsa.icfg import expansions

        return cls(
            compilation=compilation,
            contract=contract,
            expansions=expansions(contract),
            auth=auth_variables(contract),
            address_literals=address_constants(contract),
            proxy_variables=delegatecall_destinations(contract),
        )

    def taint(self, function: Function) -> ValueTaint:
        key = function.canonical_name
        if key not in self._taint:
            self._taint[key] = ValueTaint(function)
        return self._taint[key]

    def is_controlled(self, variable: object, node: Node) -> bool:
        return self.taint(node.function).is_controlled(variable)

    def guard_counter(self, expansion: Expansion) -> GuardCounter:
        return GuardCounter(expansion, self.auth)


class Detector(Protocol):
    """A static detector turns a contract into a set of targets; it never issues a verdict."""

    def detect(self, analysis: Analysis) -> list[Target]: ...


def build_target(
    analysis: Analysis,
    expansion: Expansion,
    vertex: Vertex,
    vuln_class: "VulnClass",
    key_expressions: list[object],
    op_index: int = 0,
    call_node: Optional[Node] = None,
    key_node: Optional[Node] = None,
) -> Target:
    """Assemble a target and its context, measured from the entry point of the expansion.

    `key_node` is the node the key expressions belong to. For RE and UC the target is the state
    write but E_t comes from the call, which may sit in a different function -- a call in the
    body and a write in the tail of a modifier, for instance. Ctrl must then be evaluated with
    the taint of the call's function, not the write's.
    """
    node = expansion.node(vertex)
    owner = key_node if key_node is not None else node
    guard_count, guards = analysis.guard_counter(expansion).count(vertex)
    context = Context(
        vuln_class=vuln_class,
        entry_point=expansion.entry_point,
        key_expressions=list(key_expressions),
        guards=guards,
        moves_value=moves_value(expansion),
        call_node=call_node,
    )
    return Target(
        point=ProgramPoint(function=node.function, node=node, op_index=op_index),
        context=context,
        controllable=sum(1 for e in key_expressions if analysis.is_controlled(e, owner)),
        guard_count=guard_count,
        branch_count=expansion.branch_count(vertex),
        call_depth=vertex.depth,
    )
