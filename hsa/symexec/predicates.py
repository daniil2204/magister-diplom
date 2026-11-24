"""Vulnerability predicates phi_v of chapter 2, evaluated on a symbolic state at the target.

A predicate is called by the engine once a path has reached the target node, on the state that
holds just BEFORE the target operation runs. It returns an `Outcome`: a verdict and, for UNKNOWN,
the reason, and for CONFIRMED a counterexample.

Why "just before the target operation":

* OV needs the operands as they are read, not the result the operation would store -- after
  `REF = REF - amount` the reference holds the new value, so the operands must be taken first;
* AC / DC / TO need nothing from the operation itself, only that the path reaches it (plus, for
  DC and TO, the controllability of an expression);
* UC reads the success flag r_i from the CALL event already in the trace, recorded by an earlier
  node.

So every predicate works on the state positioned before the target operation, which is also what
the linear test harness produces with `run_until`.

Only SC09 (overflow) is written here in week 3 together with the four straight-line classes
AC, TO, DC, UC. SC08 (reentrancy) needs the one-level re-entry model and is added in week 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import z3
from slither.core.declarations import Function
from slither.slithir.operations import Binary, BinaryType

from hsa.config import Config
from hsa.model import Counterexample, EventKind, UnknownReason, Verdict
from hsa.symexec.state import Environment, Machine, UnsupportedConstruct, is_signed, zero
from hsa.symexec.translator import _match_width, overflow_condition


@dataclass(frozen=True)
class Probe:
    """Everything a predicate needs about the run that is not the state itself.

    `budget` is the time left for this target in seconds; the overflow strong condition carves its
    own sub-timeout out of it.

    `controlled` holds the atoms of X_env u X_arg -- the environment symbols and the entry point's
    argument symbols, captured at the entry state. Ctrl(e) of (2.5) is then "e mentions one of
    them", which phi_DC (2.10) needs. Storage symbols are deliberately absent, so a delegatecall
    whose destination comes from storage is not controlled.
    """

    machine: Machine
    environment: Environment
    entry_point: Function
    config: Config
    budget: float
    controlled: tuple = ()


@dataclass
class Outcome:
    """The result of one predicate evaluation on one path."""

    verdict: Verdict
    reason: Optional[UnknownReason] = None
    counterexample: Optional[Counterexample] = None


# ------------------------------------------------------------------------- SC09 overflow


def check_overflow(probe: Probe, state, point, ir: Binary) -> Outcome:
    """phi_OV (2.11, 2.12): the two-level weak / strong check.

    Weak condition (2.11): exists X. PC and Ovf. The queue-level, quantifier-free question "can
    this operation wrap on this path at all".

    Strong condition (2.12): for all X_sto in D exists X_env, X_arg. PC and Ovf. The attacker wraps
    the operation for ANY realistic storage, where D bounds every integer state variable below
    2^(N-1). This is what separates a genuine overflow from one that only exists for a hand-picked
    storage value such as `balance = 2^256 - 1`.

    The verdict follows the algorithm fixed in chapter 2:

    * weak unsat                 -> REFUTED;
    * weak unknown / timeout     -> UNKNOWN solver_unknown;
    * weak sat, strong sat       -> CONFIRMED (counterexample from X_sto = 0);
    * weak sat, strong unsat     -> UNKNOWN storage_dependent;
    * weak sat, strong unknown   -> UNKNOWN solver_unknown.
    """
    from hsa.symexec.translator import value_of  # local: avoids a cycle at import time

    signed = is_signed(ir.variable_left.type) or is_signed(ir.variable_right.type)
    left = value_of(probe.machine, state, point, ir.variable_left)
    right = value_of(probe.machine, state, point, ir.variable_right)
    left, right = _match_width(left, right, signed)
    if ir.type not in (BinaryType.ADDITION, BinaryType.SUBTRACTION, BinaryType.MULTIPLICATION):
        raise UnsupportedConstruct(f"overflow predicate on {ir.type}")
    weak = overflow_condition(ir.type, left, right, signed)

    weak_status = _check([*state.pc, weak], _budget_ms(probe.budget))
    if weak_status == z3.unsat:
        return Outcome(Verdict.REFUTED)
    if weak_status != z3.sat:
        return Outcome(Verdict.UNKNOWN, UnknownReason.SOLVER_UNKNOWN)

    abstract, sto_vars, d_constraints = _abstract_storage(probe.machine, state, weak)
    strong = _strong_condition(abstract, sto_vars, d_constraints)
    strong_status = _check_strong(strong, _strong_ms(probe))
    if strong_status == z3.sat:
        return Outcome(
            Verdict.CONFIRMED,
            counterexample=_overflow_counterexample(probe, state, abstract, sto_vars),
        )
    if strong_status == z3.unsat:
        return Outcome(Verdict.UNKNOWN, UnknownReason.STORAGE_DEPENDENT)
    return Outcome(Verdict.UNKNOWN, UnknownReason.SOLVER_UNKNOWN)


# ------------------------------------------------------------------------- SC01 access control


def check_access(probe: Probe, state) -> Outcome:
    """phi_AC (2.8): a privileged operation reached under the attacker model.

    phi_AC asks nothing of the operation itself -- the attacker model (already in `state.pc` as
    sender = a* != every V_auth value and != every address literal) does all the work. So the
    verdict is just whether the path reaches the operation: sat -> CONFIRMED, unsat -> REFUTED. An
    onlyOwner guard makes `require(sender == owner)` contradict `sender != owner`, hence unsat.
    """
    return _reachability(probe, state)


# ------------------------------------------------------------------------- SC01 tx.origin


def check_tx_origin(probe: Probe, state) -> Outcome:
    """phi_TO (2.9): priv_i AND exists c in PC. origin in vars(c) AND sender not in vars(c).

    A tx.origin check authenticates the INITIATOR, not the caller, so it does not restrict a*. The
    class is confirmed when the path both reaches the operation and owes that reach to a condition
    on tx.origin that does not mention msg.sender. Without such a condition the target is still a
    plain AC case, not a TO one, so phi_TO is REFUTED here.
    """
    if not any(
        _mentions(c, probe.environment.origin) and not _mentions(c, probe.environment.sender)
        for c in state.pc
    ):
        return Outcome(Verdict.REFUTED)
    return _reachability(probe, state)


# ------------------------------------------------------------------------- SC10 delegatecall


def check_delegatecall(probe: Probe, state, point, ir) -> Outcome:
    """phi_DC (2.10): dcall_i(a) AND Ctrl(a).

    The target IS the delegatecall, so it is evaluated before the operation runs and the
    destination is read from the operand rather than from the trace. Ctrl(a) is decided exactly
    here (2.5): a destination built from X_env u X_arg is controlled, one that comes from storage
    is not. An uncontrolled destination is REFUTED without troubling the solver; a controlled one
    is CONFIRMED as soon as the path is reachable.
    """
    from hsa.symexec.translator import value_of  # local: avoids a cycle at import time

    destination = value_of(probe.machine, state, point, ir.destination)
    if not _is_controlled(probe, destination):
        return Outcome(Verdict.REFUTED)
    return _reachability(probe, state)


# ------------------------------------------------------------------------- SC06 unchecked call


def check_unchecked(probe: Probe, state) -> Outcome:
    """phi_UC (2.7): lcall_i(a, r_i) AND r_i = false AND write_j(v), j > i.

    The engine positions the state at the state write that is the target, so the write (j > i) is
    given by construction and the low-level call sits earlier in the trace. r_i is the fresh
    success flag recorded on that LCALL event; the callee is unknown code, so r_i is free unless a
    later `require(ok)` pinned it -- in which case `r_i = false` is unsat and the call was checked.
    The verdict is whether some low-level call on this path can report failure: sat -> CONFIRMED.
    """
    events = [e for e in state.tau if e.kind is EventKind.LCALL and e.result is not None]
    if not events:
        return Outcome(Verdict.REFUTED)
    unknown = False
    for event in events:
        status, model = _solve([*state.pc, z3.Not(event.result)], _budget_ms(probe.budget))
        if status == z3.sat:
            return Outcome(Verdict.CONFIRMED, counterexample=_counterexample(probe, state, model))
        if status != z3.unsat:
            unknown = True
    if unknown:
        return Outcome(Verdict.UNKNOWN, UnknownReason.SOLVER_UNKNOWN)
    return Outcome(Verdict.REFUTED)


# ------------------------------------------------- reachability and counterexample (AC/TO/DC)


def _reachability(probe: Probe, state) -> Outcome:
    """The shared `exists X: PC` check: sat -> CONFIRMED with a witness, unsat -> REFUTED."""
    status, model = _solve([*state.pc], _budget_ms(probe.budget))
    if status == z3.unsat:
        return Outcome(Verdict.REFUTED)
    if status != z3.sat:
        return Outcome(Verdict.UNKNOWN, UnknownReason.SOLVER_UNKNOWN)
    return Outcome(Verdict.CONFIRMED, counterexample=_counterexample(probe, state, model))


def _counterexample(probe: Probe, state, model: z3.ModelRef) -> Counterexample:
    """Read the entry point's arguments and the environment out of a satisfying model."""
    arguments = {}
    for parameter in probe.entry_point.parameters:
        term = state.rho.get(parameter.name)
        if isinstance(term, z3.ExprRef):
            arguments[parameter.name] = model.eval(term, model_completion=True)
    return Counterexample(
        function=probe.entry_point.canonical_name,
        arguments=arguments,
        sender=model.eval(probe.environment.sender, model_completion=True),
        value=model.eval(probe.environment.value, model_completion=True),
    )


def _is_controlled(probe: Probe, expr: z3.ExprRef) -> bool:
    """Ctrl(e) of (2.5): does `expr` depend on any atom of X_env u X_arg?"""
    controlled = {term.get_id() for term in probe.controlled}
    return any(const.get_id() in controlled for const in _constants(expr))


def _mentions(constraint: z3.BoolRef, symbol: z3.ExprRef) -> bool:
    return any(const.get_id() == symbol.get_id() for const in _constants(constraint))


def _strong_condition(
    formula: z3.BoolRef, sto_vars: list[z3.ExprRef], d_constraints: list[z3.BoolRef]
) -> z3.BoolRef:
    """for all X_sto in D exists X_env, X_arg. formula.

    `formula` is already (PC and Ovf) with every storage term replaced by a fresh variable, so the
    universally quantified variables are exactly `sto_vars`. Whatever is left free is X_env / X_arg
    and is quantified existentially. With no storage term the strong condition degenerates to the
    weak one, which is why an overflow that touches no storage (BEC `cnt * value`) is CONFIRMED.
    """
    others = [c for c in _constants(formula) if not _contains(sto_vars, c)]
    inner = z3.Exists(others, formula) if others else formula
    if not sto_vars:
        return inner
    return z3.ForAll(sto_vars, z3.Implies(z3.And(*d_constraints), inner))


def _overflow_counterexample(
    probe: Probe, state, abstract: z3.BoolRef, sto_vars: list[z3.ExprRef]
) -> Optional[Counterexample]:
    """The witness that goes into the report: fix X_sto = 0 and solve exists X_env, X_arg.

    The strong condition is a Skolem function, not a value, so it cannot be printed. 0 lies in D
    and the strong condition guarantees a witness there, so this solve is always sat once the
    strong condition held.
    """
    solver = z3.Solver()
    solver.add(abstract)
    for variable in sto_vars:
        solver.add(variable == zero(variable.sort()))
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    arguments = {}
    for parameter in probe.entry_point.parameters:
        term = state.rho.get(parameter.name)
        if isinstance(term, z3.ExprRef):
            arguments[parameter.name] = model.eval(term, model_completion=True)
    return Counterexample(
        function=probe.entry_point.canonical_name,
        arguments=arguments,
        sender=model.eval(probe.environment.sender, model_completion=True),
        value=model.eval(probe.environment.value, model_completion=True),
    )


# --------------------------------------------------------------- storage abstraction (OV)


def _abstract_storage(
    machine: Machine, state, weak: z3.BoolRef
) -> tuple[z3.BoolRef, list[z3.ExprRef], list[z3.BoolRef]]:
    """Replace every storage term in (PC and Ovf) with a fresh variable, innermost first.

    "Storage term" is a scalar state variable or a `Select` whose array traces back to one. Each
    distinct term becomes a fresh variable bounded by D. Two reads of the same mapping at different
    keys are different terms and so become INDEPENDENT variables: the abstraction deliberately
    loses aliasing (`balances[a]` and `balances[b]` even when a = b). For the universal of the
    strong condition that is the safe direction -- it only makes the overflow harder to confirm.

    Innermost-first means a nested read such as `Select(Store(orig, k, Select(orig, k) - v), j)`
    is reduced from the inside out, so no replaced term is ever left inside another.
    """
    names = _storage_leaf_names(machine)
    formula = z3.And(*state.pc, weak) if state.pc else weak
    sto_vars: list[z3.ExprRef] = []
    d_constraints: list[z3.BoolRef] = []
    while True:
        term = _innermost_storage_term(formula, names)
        if term is None:
            break
        fresh = machine.fresh("sto", term.sort())
        formula = z3.substitute(formula, (term, fresh))
        sto_vars.append(fresh)
        d_constraints.append(_in_domain(fresh))
    return formula, sto_vars, d_constraints


def _in_domain(variable: z3.ExprRef) -> z3.BoolRef:
    """D: an integer state variable of width N is below 2^(N-1).

    Written for unsigned storage, which is every state variable in the current fixtures. Signed
    storage would use |x| < 2^(N-2); it is deferred until a fixture needs it, and this is a
    recorded limitation rather than a silent one.
    """
    width = variable.size()
    return z3.ULT(variable, z3.BitVecVal(2 ** (width - 1), width))


def _storage_leaf_names(machine: Machine) -> frozenset[str]:
    """The flattened leaf names of every state variable, e.g. `balances`, `accounts.balance`."""
    from hsa.symexec.state import flatten  # local: keeps the module's import list flat

    names: set[str] = set()
    for variable in machine.contract.state_variables:
        try:
            leaves = flatten(variable.type)
        except UnsupportedConstruct:
            continue
        for path, _ in leaves:
            names.add(".".join((variable.name,) + path))
    return frozenset(names)


def _innermost_storage_term(expr: z3.ExprRef, names: frozenset[str]) -> Optional[z3.ExprRef]:
    """A storage term none of whose sub-terms is itself a storage term (post-order search)."""
    for child in expr.children():
        found = _innermost_storage_term(child, names)
        if found is not None:
            return found
    return expr if _is_storage_term(expr, names) else None


def _is_storage_term(expr: z3.ExprRef, names: frozenset[str]) -> bool:
    if not isinstance(expr, z3.BitVecRef):
        return False  # only scalar reads are abstracted; arrays appear only inside a Select
    if _is_storage_const(expr, names):
        return True
    if z3.is_select(expr):
        return _is_storage_const(_peel_array(expr.arg(0)), names)
    return False


def _peel_array(array: z3.ExprRef) -> z3.ExprRef:
    """Strip Store and Select layers to reach the array constant a read ultimately comes from."""
    while True:
        if z3.is_store(array) or z3.is_select(array):
            array = array.arg(0)
        else:
            return array


def _is_storage_const(expr: z3.ExprRef, names: frozenset[str]) -> bool:
    if not (z3.is_const(expr) and expr.decl().kind() == z3.Z3_OP_UNINTERPRETED):
        return False
    return expr.decl().name().rsplit("!", 1)[0] in names


# ------------------------------------------------------------------------------ z3 helpers


def _constants(expr: z3.ExprRef) -> list[z3.ExprRef]:
    """The free uninterpreted constants of a formula, each once, in a stable order."""
    seen: set[int] = set()
    out: list[z3.ExprRef] = []

    def walk(node: z3.ExprRef) -> None:
        if node.get_id() in seen:
            return
        seen.add(node.get_id())
        if node.num_args() == 0 and node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            out.append(node)
            return
        for child in node.children():
            walk(child)

    walk(expr)
    return out


def _contains(variables: list[z3.ExprRef], candidate: z3.ExprRef) -> bool:
    return any(candidate.get_id() == variable.get_id() for variable in variables)


def _check(constraints: list[z3.BoolRef], timeout_ms: int) -> z3.CheckSatResult:
    solver = z3.Solver()
    if timeout_ms > 0:
        solver.set("timeout", timeout_ms)
    solver.add(*constraints)
    return solver.check()


def _solve(
    constraints: list[z3.BoolRef], timeout_ms: int
) -> tuple[z3.CheckSatResult, Optional[z3.ModelRef]]:
    """Like `_check`, but also hands back the model when the answer is sat (for counterexamples)."""
    solver = z3.Solver()
    if timeout_ms > 0:
        solver.set("timeout", timeout_ms)
    solver.add(*constraints)
    status = solver.check()
    return status, solver.model() if status == z3.sat else None


def _check_strong(strong: z3.BoolRef, timeout_ms: int) -> z3.CheckSatResult:
    """Decide the strong condition with quantifier elimination, not MBQI.

    The strong condition is `for all X_sto in D exists X_env, X_arg. PC and Ovf`, an alternating
    bitvector formula. Z3's default engine (MBQI) returns `unknown` on it even for the trivial
    control cases such as `for all b < 2^255 exists a. b <u a`. The `qe2` tactic eliminates the
    quantifiers first, which turns those into a decidable ground problem; `smt` then closes it. On
    a genuine storage dependence the eliminated formula is still unsat, so the verdict split from
    chapter 2 is preserved.
    """
    solver = z3.Then("qe2", "default").solver()
    if timeout_ms > 0:
        solver.set("timeout", timeout_ms)
    solver.add(strong)
    return solver.check()


def _budget_ms(budget: float) -> int:
    return max(0, int(budget * 1000))


def _strong_ms(probe: Probe) -> int:
    """Sub-timeout of the strong condition: clamp(fraction * B_t, min, max), capped by B_t."""
    config = probe.config
    seconds = min(
        max(config.ov_strong_fraction * probe.budget, config.ov_strong_min),
        config.ov_strong_max,
        probe.budget,
    )
    return max(0, int(seconds * 1000))
