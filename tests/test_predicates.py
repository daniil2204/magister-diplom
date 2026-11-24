"""Tests for the vulnerability predicates (chapter 2), evaluated on a linear symbolic state.

Only the OV predicate is exercised here through the linear harness: every OV fixture below is
straight-line, so `run_until` reaches the target operation with exactly the PC the engine would
build. The verdicts asserted are the hand-derived ones written in each fixture's header comment.

Modifier-guarded OV negatives (Overflow_args.mulOwner, Mint_internal.mint) cannot be reached by the
linear harness -- it skips modifier calls -- so they belong to the engine tests, not here.
"""

from __future__ import annotations

from hsa.config import Config
from hsa.model import ProgramPoint, UnknownReason, Verdict
from hsa.static.base import is_delegatecall
from hsa.symexec.predicates import (
    Probe,
    check_access,
    check_delegatecall,
    check_overflow,
    check_tx_origin,
    check_unchecked,
)
from hsa.symexec.translator import execute
from tests.test_symexec import addition, multiplication, run_until, setup, subtraction


def _probe(machine, environment, point, budget: float = 120.0) -> Probe:
    return Probe(
        machine=machine,
        environment=environment,
        entry_point=point.function,
        config=Config(),
        budget=budget,
    )


def _check(name: str, function_name: str, wanted):
    machine, environment, state, point, ir = run_until(name, function_name, wanted)
    return check_overflow(_probe(machine, environment, point), state, point, ir)


def _controlled(environment, function, state) -> tuple:
    """Atoms of X_env u X_arg, captured on the entry state before any reassignment."""
    return tuple(environment.terms().values()) + tuple(
        state.rho[p.name] for p in function.parameters if p.name in state.rho
    )


def run_body(name: str, function_name: str):
    """Execute the whole body (modifier calls skipped) and return a probe plus the final state."""
    machine, environment, state, function = setup(name, function_name)
    controlled = _controlled(environment, function, state)
    for node in function.nodes:
        for index, ir in enumerate(node.irs):
            if getattr(ir, "is_modifier_call", False):
                continue
            execute(machine, state, ProgramPoint(node.function, node, index), ir)
    probe = Probe(machine, environment, function, Config(), 120.0, controlled)
    return probe, state


def reach(name: str, function_name: str, wanted):
    """Stop just before the first operation satisfying `wanted`; capture X_env u X_arg at entry."""
    machine, environment, state, function = setup(name, function_name)
    controlled = _controlled(environment, function, state)
    for node in function.nodes:
        for index, ir in enumerate(node.irs):
            point = ProgramPoint(node.function, node, index)
            if wanted(ir):
                return Probe(machine, environment, function, Config(), 120.0, controlled), state, point, ir
            execute(machine, state, point, ir)
    raise AssertionError(f"no matching operation in {function_name}")


# ----------------------------------------------------------------- CONFIRMED by the strong condition


def test_sub_underflow_is_confirmed() -> None:
    """`balances[msg.sender] -= amount` with no guard: for every balance < 2^255 pick amount+1."""
    outcome = _check("Overflow_sub", "withdrawAll", subtraction)
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_mul_without_storage_is_confirmed() -> None:
    """`2 * _value` touches no storage, so the strong condition degenerates to the weak one."""
    outcome = _check("Overflow_mul", "batch2", multiplication)
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_both_arguments_controlled_is_confirmed() -> None:
    """`_a * _b`, both arguments, no storage -> CONFIRMED (A = 1 case for the sensitivity run)."""
    outcome = _check("Overflow_args", "mulArgs", multiplication)
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


# --------------------------------------------------------------------------------------- REFUTED


def test_guarded_sub_is_refuted() -> None:
    """`require(balances[msg.sender] >= v); balances[msg.sender] -= v` cannot underflow."""
    outcome = _check("Overflow_guarded", "burn", subtraction)
    assert outcome.verdict is Verdict.REFUTED


def test_transfer_sub_is_refuted() -> None:
    outcome = _check("Overflow_transfer", "transfer", subtraction)
    assert outcome.verdict is Verdict.REFUTED


def test_mul_guarded_sub_is_refuted() -> None:
    outcome = _check("Overflow_mul", "batch2", subtraction)
    assert outcome.verdict is Verdict.REFUTED


# ----------------------------------------------------------------- UNKNOWN storage_dependent


def test_transfer_add_is_storage_dependent() -> None:
    """`balances[to] += v`: in D both operands are < 2^255 so no wrap; weak sat, strong unsat."""
    outcome = _check("Overflow_transfer", "transfer", addition)
    assert outcome.verdict is Verdict.UNKNOWN
    assert outcome.reason is UnknownReason.STORAGE_DEPENDENT


def test_mul_add_is_storage_dependent() -> None:
    outcome = _check("Overflow_mul", "batch2", addition)
    assert outcome.verdict is Verdict.UNKNOWN
    assert outcome.reason is UnknownReason.STORAGE_DEPENDENT


# ------------------------------------------------------------------------------ SC01 access control


def test_unprotected_write_is_confirmed_access_control() -> None:
    """`owner = n` with no guard: any a* reaches the write, so phi_AC holds."""
    probe, state = run_body("Access_unprotected", "setOwner")
    outcome = check_access(probe, state)
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_sender_guard_refutes_access_control() -> None:
    """With `sender == owner` on the path (what onlyOwner adds) the attacker model makes it unsat.

    The engine builds this PC by inlining the modifier; here the guard is added directly, on the
    ENTRY state, against the original `owner` symbol -- the same one the attacker model constrains,
    and the one a modifier sees before the body overwrites it. That is what makes it REFUTED.
    """
    machine, environment, state, function = setup("Access_unprotected", "setOwner")
    state.pc.append(environment.sender == state.mu["AccessUnprotected.owner"])
    probe = Probe(machine, environment, function, Config(), 120.0)
    outcome = check_access(probe, state)
    assert outcome.verdict is Verdict.REFUTED


# ------------------------------------------------------------------------------ SC01 tx.origin


def test_origin_check_is_confirmed_tx_origin() -> None:
    """`require(tx.origin == owner)` reaches the write with sender = a* and origin = owner."""
    probe, state = run_body("Tx_origin", "setOwnerOrigin")
    outcome = check_tx_origin(probe, state)
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_no_origin_condition_refutes_tx_origin() -> None:
    """setOwnerSender has no tx.origin condition, so phi_TO (2.9) finds no such c in PC."""
    probe, state = run_body("Tx_origin", "setOwnerSender")
    outcome = check_tx_origin(probe, state)
    assert outcome.verdict is Verdict.REFUTED


# ------------------------------------------------------------------------------ SC10 delegatecall


def test_argument_destination_is_confirmed_delegatecall() -> None:
    """`target.delegatecall(data)`: the destination is an argument, so Ctrl(a) holds."""
    probe, state, point, ir = reach("Delegatecall_proxy", "forward", is_delegatecall)
    outcome = check_delegatecall(probe, state, point, ir)
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_storage_destination_is_refuted_delegatecall() -> None:
    """`implementation.delegatecall(data)`: the destination is storage, so Ctrl(a) is false."""
    probe, state, point, ir = reach("Delegatecall_proxy", "run", is_delegatecall)
    outcome = check_delegatecall(probe, state, point, ir)
    assert outcome.verdict is Verdict.REFUTED


# ------------------------------------------------------------------------------ SC06 unchecked call


def test_discarded_call_result_is_confirmed_unchecked() -> None:
    """`to.call{value}("")` then a write: the callee may revert, so r = false is reachable."""
    probe, state = run_body("Unchecked_call", "payout")
    outcome = check_unchecked(probe, state)
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_discarded_send_result_is_confirmed_unchecked() -> None:
    """`send` reports failure through a return value too (Slither's unchecked-send)."""
    probe, state = run_body("Unchecked_call", "payoutSend")
    outcome = check_unchecked(probe, state)
    assert outcome.verdict is Verdict.CONFIRMED


def test_required_call_result_is_refuted_unchecked() -> None:
    """`require(ok)` pins the flag true, so `r = false` is unsat and the call was checked."""
    probe, state = run_body("Unchecked_call", "payoutChecked")
    outcome = check_unchecked(probe, state)
    assert outcome.verdict is Verdict.REFUTED
