"""Tests for the symbolic state and the SlithIR translator (table 2.1).

The helpers execute a function LINEARLY, node by node. That is correct only for the straight-line
fixtures used here; choosing branches is the engine's job (week 3), not the translator's.

Several assertions check the expectations the thesis states in words -- that the subtraction in
`Overflow_transfer` cannot underflow while the one in `Overflow_sub` can, and that the attacker
model makes an onlyOwner path unsatisfiable. Those are the method's own claims, so a failure here
means the method and the code disagree.
"""

from __future__ import annotations

import pytest
import z3
from slither.core.cfg.node import NodeType
from slither.core.solidity_types import ElementaryType
from slither.slithir.operations import Binary, BinaryType, SolidityCall

from hsa.model import EventKind, ProgramPoint
from hsa.static.base import address_constants, auth_variables
from hsa.symexec.state import (
    ADDRESS_BITS,
    BYTES,
    VALUE_BITS,
    WORD_BITS,
    AttackerModel,
    Environment,
    Machine,
    UnsupportedConstruct,
    environment_constraints,
    flatten,
    sort_of,
)
from hsa.symexec.translator import (
    UNINTERPRETED,
    condition_of,
    double_width_overflow,
    execute,
    execute_node,
    overflow_condition,
    value_of,
)
from tests.conftest import load


def setup(name: str, function_name: str):
    """Machine, environment and Sigma_0 with the attacker model already in PC."""
    compilation = load(name)
    contract = compilation.slither.contracts[0]
    machine = Machine(contract, compilation.checked_arithmetic)
    environment = machine.new_environment()
    function = next(
        f
        for f in list(contract.functions) + list(contract.modifiers)
        if f.name == function_name
    )
    state = machine.initial_state(function, environment)
    attacker = AttackerModel.build(auth_variables(contract), address_constants(contract))
    state.pc.extend(attacker.constraints(state, environment))
    return machine, environment, state, function


def run(name: str, function_name: str):
    """Execute the body only: a MODIFIER_CALL is skipped, not inlined.

    Inlining modifiers is the engine's job (week 3). Skipping one here means the guard inside it
    is missing from PC, so no test below may depend on a modifier's effect -- `onlyOwner` is run
    directly as its own function instead.
    """
    machine, environment, state, function = setup(name, function_name)
    for node in function.nodes:
        for index, ir in enumerate(node.irs):
            if getattr(ir, "is_modifier_call", False):
                continue
            execute(machine, state, ProgramPoint(node.function, node, index), ir)
    return machine, environment, state


def body_conditions(state, environment: Environment) -> list:
    """PC without what Sigma_0 already starts with, i.e. only what the body itself added."""
    prefix = {str(c) for c in environment_constraints(environment)}
    return [c for c in state.pc if str(c) not in prefix]


def run_until(name: str, function_name: str, wanted):
    """Stop just before the first operation satisfying `wanted`, and return it unexecuted."""
    machine, environment, state, function = setup(name, function_name)
    for node in function.nodes:
        for index, ir in enumerate(node.irs):
            point = ProgramPoint(node.function, node, index)
            if wanted(ir):
                return machine, environment, state, point, ir
            execute(machine, state, point, ir)
    raise AssertionError(f"no matching operation in {function_name}")


def subtraction(ir) -> bool:
    return isinstance(ir, Binary) and ir.type is BinaryType.SUBTRACTION


def multiplication(ir) -> bool:
    return isinstance(ir, Binary) and ir.type is BinaryType.MULTIPLICATION


def addition(ir) -> bool:
    return isinstance(ir, Binary) and ir.type is BinaryType.ADDITION


def word(value: int) -> z3.BitVecNumRef:
    return z3.BitVecVal(value, WORD_BITS)


def satisfiable(*constraints) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat


# ----------------------------------------------------------------------------- sorts


def test_sorts_follow_table_2_1() -> None:
    assert sort_of(ElementaryType("uint256")) == z3.BitVecSort(WORD_BITS)
    assert sort_of(ElementaryType("uint8")) == z3.BitVecSort(8)
    assert sort_of(ElementaryType("int128")) == z3.BitVecSort(128)
    assert sort_of(ElementaryType("address")) == z3.BitVecSort(ADDRESS_BITS)
    assert sort_of(ElementaryType("bytes32")) == z3.BitVecSort(WORD_BITS)
    assert sort_of(ElementaryType("bytes")) == BYTES


def test_bool_is_a_bool_not_an_eight_bit_vector() -> None:
    """Slither reports size 8 for `bool`; using it would make `require` take a bitvector."""
    assert sort_of(ElementaryType("bool")) == z3.BoolSort()


def test_mapping_becomes_an_array() -> None:
    contract = load("Vault").slither.contracts[0]
    balances = next(v for v in contract.state_variables if v.name == "balances")
    assert sort_of(balances.type) == z3.ArraySort(
        z3.BitVecSort(ADDRESS_BITS), z3.BitVecSort(WORD_BITS)
    )


def test_an_unmodelled_type_is_refused_rather_than_guessed() -> None:
    with pytest.raises(UnsupportedConstruct):
        sort_of(None)


# ------------------------------------------------------------------- initial state


def test_storage_starts_as_free_symbols() -> None:
    """X_sto is arbitrary at the start of the transaction (2.3): a free symbol in Sigma_0."""
    _, _, state, _ = setup("Vault", "deposit")
    balances = state.mu["Vault.balances"]
    assert z3.is_app(balances) and balances.decl().arity() == 0
    assert balances.sort() == z3.ArraySort(
        z3.BitVecSort(ADDRESS_BITS), z3.BitVecSort(WORD_BITS)
    )


def test_the_environment_is_bound_once_per_transaction() -> None:
    machine, environment, state = run("Vault", "withdraw")
    # X_env lives in state.env, not rho, so a call frame's save/restore of rho never touches it.
    assert state.env["msg.sender"] is environment.sender
    assert state.env["msg.value"] is environment.value


def test_translation_is_deterministic() -> None:
    """Two runs over the same contract must build byte-identical formulas."""
    first = [str(c) for c in run("Overflow_mul", "batch2")[2].pc]
    second = [str(c) for c in run("Overflow_mul", "batch2")[2].pc]
    assert first == second


# ------------------------------------------------------------------ attacker model


def test_attacker_cannot_be_the_owner() -> None:
    """`require(msg.sender == owner)` is unsatisfiable: this is what makes mulOwner REFUTED."""
    _, _, state = run("Overflow_args", "onlyOwner")
    assert not satisfiable(*state.pc)


def test_without_the_attacker_model_the_same_path_is_satisfiable() -> None:
    """The guard itself is fine; it is the model of (1.2) that rules the path out."""
    machine, _, state, function = setup("Overflow_args", "onlyOwner")
    state.pc.clear()
    for node in function.nodes:
        execute_node(machine, state, node)
    assert satisfiable(*state.pc)


# ----------------------------------------------------------- checked vs unchecked


def test_solidity_08_adds_not_overflow_to_the_path_condition() -> None:
    """`balances[msg.sender] += msg.value` in 0.8 continues only on the non-overflowing path."""
    _, environment, state = run("Vault", "deposit")
    conditions = body_conditions(state, environment)
    assert len(conditions) == 1
    assert z3.is_not(conditions[0])
    assert not [e for e in state.tau if e.kind is EventKind.UNCHECKED_OP]


def test_below_solidity_08_every_operation_is_unchecked() -> None:
    """batch2 has four arithmetic operations and 0.4.24 checks none of them."""
    _, _, state = run("Overflow_mul", "batch2")
    assert len([e for e in state.tau if e.kind is EventKind.UNCHECKED_OP]) == 4
    assert [str(c) for c in state.pc] == [str(c) for c in state.pc if not z3.is_not(c)]


# ------------------------------------------------------------- the weak condition


def test_unguarded_subtraction_can_underflow() -> None:
    """Overflow_sub: `balances[msg.sender] -= amount` with no require -- the thesis says sat."""
    machine, _, state, point, ir = run_until("Overflow_sub", "withdrawAll", subtraction)
    left = value_of(machine, state, point, ir.variable_left)
    right = value_of(machine, state, point, ir.variable_right)
    assert satisfiable(*state.pc, overflow_condition(ir.type, left, right, False))


def test_a_require_removes_the_underflow() -> None:
    """Overflow_transfer: `require(balances[msg.sender] >= v)` makes the weak condition unsat."""
    machine, _, state, point, ir = run_until("Overflow_transfer", "transfer", subtraction)
    left = value_of(machine, state, point, ir.variable_left)
    right = value_of(machine, state, point, ir.variable_right)
    assert not satisfiable(*state.pc, overflow_condition(ir.type, left, right, False))


def test_the_bec_multiplication_can_overflow() -> None:
    """`2 * _value` touches no storage at all, which is why the thesis expects CONFIRMED."""
    machine, _, state, point, ir = run_until("Overflow_mul", "batch2", multiplication)
    left = value_of(machine, state, point, ir.variable_left)
    right = value_of(machine, state, point, ir.variable_right)
    assert satisfiable(*state.pc, overflow_condition(ir.type, left, right, False))


def test_the_loop_overflows_only_on_the_second_iteration() -> None:
    """Overflow_loop: the claim the fixture is built on, checked at the level of the formula.

    The engine does the unrolling (week 3); here the loop body is applied by hand once and then
    twice. First visit: acc = 0, so Ovf_+(0, step) is false for every step and k = 1 must give
    REFUTED. Second visit: acc = step, so Ovf_+(step, step) is satisfiable and k = 2 must give
    CONFIRMED, with step = 2^255 as the witness.
    """
    machine, _, state, function = setup("Overflow_loop", "accumulate")
    body = next(n for n in function.nodes if "acc += step" in str(n))
    preamble = [n for n in function.nodes if n.node_id < body.node_id]
    for node in preamble:
        execute_node(machine, state, node)

    def weak_condition() -> z3.BoolRef:
        point = ProgramPoint(body.function, body, 0)
        ir = next(ir for ir in body.irs if isinstance(ir, Binary))
        left = value_of(machine, state, point, ir.variable_left)
        right = value_of(machine, state, point, ir.variable_right)
        return overflow_condition(ir.type, left, right, False)

    first = weak_condition()
    assert not satisfiable(*state.pc, first)  # k = 1 -> REFUTED

    execute_node(machine, state, body)
    second = weak_condition()
    assert satisfiable(*state.pc, second)  # k = 2 -> CONFIRMED

    step = state.rho["step"]
    assert satisfiable(*state.pc, second, step == z3.BitVecVal(2**255, WORD_BITS))
    # No storage term enters the formula, so the universal quantifier of the strong condition is
    # vacuous: this is why the verdict is CONFIRMED and not UNKNOWN `storage_dependent`.
    assert "total" not in str(second)


@pytest.mark.parametrize(
    "function_name, left, right, expected",
    [
        # 2^255 + 2^255 wraps to 0 in 256 bits, but addmod sees 2^256, and 2^256 = 2 (mod 7).
        ("addRing", 2**255, 2**255, 2),
        # 2^128 * 2^128 wraps to 0 in the same way.
        ("mulRing", 2**128, 2**128, 2),
    ],
)
def test_addmod_and_mulmod_are_computed_exactly(
    function_name: str, left: int, right: int, expected: int
) -> None:
    """Both are reduced modulo k only after the exact operation, so 2N bits are needed."""
    machine, _, state, function = setup("Modular", function_name)
    result = None
    for node in function.nodes:
        for index, ir in enumerate(node.irs):
            execute(machine, state, ProgramPoint(node.function, node, index), ir)
            if isinstance(ir, SolidityCall):
                result = state.rho[ir.lvalue.name]
    assert result is not None

    x, y, k = state.rho["x"], state.rho["y"], state.rho["k"]
    assert not satisfiable(x == word(left), y == word(right), k == word(7), result != word(expected))
    assert not satisfiable(*state.pc, k == word(0))  # k = 0 reverts, as for `/` and `%`


def test_the_bound_on_msg_value_is_what_keeps_donate_out_of_confirmed() -> None:
    """SimpleDAO.donate: `credit[to] += msg.value` over D, with and without the bound.

    Over D the storage term is below 2^255, so the sum can only wrap if msg.value reaches up into
    the same range. No attacker can send that much ether, and without the bound the solver would
    report this as a confirmed overflow -- a false positive of the model, not of the contract.
    """
    machine, environment, state, point, ir = run_until("SimpleDAO_orig", "donate", addition)
    left = value_of(machine, state, point, ir.variable_left)  # credit[to]
    right = value_of(machine, state, point, ir.variable_right)  # msg.value
    weak = overflow_condition(ir.type, left, right, False)
    inside_d = z3.ULT(left, z3.BitVecVal(2**(WORD_BITS - 1), WORD_BITS))

    assert satisfiable(*state.pc, weak)  # storage is free, so the weak condition holds
    assert not satisfiable(*state.pc, weak, inside_d)  # -> UNKNOWN `storage_dependent`
    assert satisfiable(*body_conditions(state, environment), weak, inside_d)  # -> CONFIRMED


def test_overflow_condition_matches_the_thesis_formulas() -> None:
    x, y = z3.BitVecs("x y", 8)
    assert not satisfiable(
        overflow_condition(BinaryType.ADDITION, x, y, False) != z3.ULT(x + y, x)
    )
    assert not satisfiable(
        overflow_condition(BinaryType.SUBTRACTION, x, y, False) != z3.ULT(x, y)
    )
    assert not satisfiable(
        overflow_condition(BinaryType.MULTIPLICATION, x, y, False)
        != z3.And(y != 0, z3.UDiv(x * y, y) != x)
    )


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize(
    "operation",
    [BinaryType.ADDITION, BinaryType.SUBTRACTION, BinaryType.MULTIPLICATION],
)
def test_overflow_condition_matches_the_double_width_definition(operation, signed) -> None:
    """Ovf is DEFINED as "the N-bit result differs from the exact one"; the code computes it
    with Z3's predicates. Unsat here means the two agree on every pair of 8-bit values, which
    is what makes the signed forms usable in the thesis without a hand proof."""
    x, y = z3.BitVecs("x y", 8)
    assert not satisfiable(
        overflow_condition(operation, x, y, signed)
        != double_width_overflow(operation, x, y, signed)
    )


# ---------------------------------------------------------------- mappings and refs


def test_writing_through_a_reference_updates_only_that_key() -> None:
    """`balances[msg.sender] = 0` is a Store; every other key keeps its symbolic value."""
    machine, environment, state = run("Vault", "withdraw")
    balances = state.mu["Vault.balances"]
    other = z3.BitVec("other", ADDRESS_BITS)
    assert not satisfiable(z3.Select(balances, environment.sender) != 0)
    assert satisfiable(other != environment.sender, z3.Select(balances, other) != 0)


# --------------------------------------------------------------------- structs


BALANCE = "Struct_bank.accounts.balance"
NONCE = "Struct_bank.accounts.nonce"


def test_a_struct_becomes_one_term_per_field() -> None:
    """mapping(address => Account) is two arrays, not an array of a struct sort."""
    _, _, state, _ = setup("Struct_bank", "deposit")
    assert "Struct_bank.accounts" not in state.mu
    for name in (BALANCE, NONCE):
        assert state.mu[name].sort() == z3.ArraySort(
            z3.BitVecSort(ADDRESS_BITS), z3.BitVecSort(WORD_BITS)
        )


def test_nested_containers_flatten_recursively() -> None:
    """The field path picks the term, the keys stay in their original order.

    `deeps[i].m[j].a` must read Select(Select(deeps.m.a, i), j): the outer mapping key first.
    Checking the sorts is the same statement, written as types.
    """
    contract = load("Struct_nested").slither.contracts[0]
    word, address = z3.BitVecSort(WORD_BITS), z3.BitVecSort(ADDRESS_BITS)
    flattened = {
        variable.name: {".".join(path): sort for path, sort in flatten(variable.type)}
        for variable in contract.state_variables
    }
    assert flattened["one"] == {"inner.a": word, "inner.who": address, "b": word}
    assert flattened["row"] == {
        "inner.a": z3.ArraySort(word, word),
        "inner.who": z3.ArraySort(word, address),
        "b": z3.ArraySort(word, word),
    }
    assert flattened["deeps"] == {
        "m.a": z3.ArraySort(word, z3.ArraySort(word, word)),
        "m.who": z3.ArraySort(word, z3.ArraySort(word, address)),
        "c": z3.ArraySort(word, word),
    }


def test_writing_one_field_leaves_the_other_untouched() -> None:
    """The independence of fields, which is the whole point of flattening."""
    machine, _, state, function = setup("Struct_bank", "bump")
    before = state.mu[BALANCE]
    for node in function.nodes:
        execute_node(machine, state, node)
    assert state.mu[BALANCE] is before
    assert state.mu[NONCE] is not before


def test_a_storage_pointer_writes_through_to_storage() -> None:
    """`Account storage account = accounts[who]` is a reference: `account.balance = v` lands."""
    machine, _, state, function = setup("Struct_bank", "peek")
    for node in function.nodes:
        execute_node(machine, state, node)
    who, value = state.rho["who"], state.rho["value"]
    assert not satisfiable(z3.Select(state.mu[BALANCE], who) != value)


def test_a_memory_copy_does_not_write_through() -> None:
    """Same SlithIR as `peek`, only the declared data location differs -- and it decides.

    If this ever flips, every struct contract gets invented writes after its external calls,
    i.e. invented SC08 confirmations.
    """
    machine, _, state, function = setup("Struct_bank", "snapshot")
    before = state.mu[BALANCE]
    for node in function.nodes:
        execute_node(machine, state, node)
    assert state.mu[BALANCE] is before
    assert state.rho["account.balance"] is state.rho["value"]


def test_the_memory_copy_starts_from_the_values_it_copied() -> None:
    """`Outer memory o = one` copies the Select terms as they are at the moment of the copy."""
    machine, _, state, function = setup("Struct_nested", "copyOut")
    before = state.mu["Struct_nested.one.inner.a"]
    for node in function.nodes:
        execute_node(machine, state, node)
    assert state.rho["o.inner.a"] is before


def test_delete_zeroes_every_field() -> None:
    machine, _, state, function = setup("Struct_nested", "wipeOne")
    for node in function.nodes:
        execute_node(machine, state, node)
    for leaf in ("inner.a", "inner.who", "b"):
        assert state.mu[f"Struct_nested.one.{leaf}"].as_long() == 0


def test_deleting_a_struct_that_holds_a_mapping_is_refused() -> None:
    """Solidity's `delete` skips the mapping; the method does not model that, so: unsupported."""
    machine, _, state, function = setup("Struct_nested", "wipeDeep")
    with pytest.raises(UnsupportedConstruct):
        for node in function.nodes:
            execute_node(machine, state, node)


def test_a_struct_literal_fills_the_fields_in_declaration_order() -> None:
    machine, _, state, function = setup("Struct_nested", "setOne")
    for node in function.nodes:
        execute_node(machine, state, node)
    assert state.mu["Struct_nested.one.inner.a"] is state.rho["v"]
    assert state.mu["Struct_nested.one.inner.who"] is state.rho["w"]
    assert state.mu["Struct_nested.one.b"] is state.rho["v"]


def test_a_write_deep_inside_keeps_the_key_order() -> None:
    machine, _, state, function = setup("Struct_nested", "setDeep")
    untouched = state.mu["Struct_nested.deeps.m.who"]
    for node in function.nodes:
        execute_node(machine, state, node)
    i, j, v = state.rho["i"], state.rho["j"], state.rho["v"]
    written = z3.Select(z3.Select(state.mu["Struct_nested.deeps.m.a"], i), j)
    assert not satisfiable(written != v)
    assert not satisfiable(z3.Select(state.mu["Struct_nested.deeps.c"], i) != v)
    assert state.mu["Struct_nested.deeps.m.who"] is untouched


# ----------------------------------------------------------------- path condition


def test_require_lands_in_the_path_condition() -> None:
    """withdraw: require(amount > 0) and require(ok). The lock test belongs to g(t), not here."""
    _, environment, state = run("Vault", "withdraw")
    assert len(body_conditions(state, environment)) == 2


def test_a_failing_require_closes_the_path() -> None:
    """The reverting branch is PC and not(c). Vault.withdraw: not(amount > 0) and amount = 0."""
    machine, environment, state, function = setup("Vault", "withdraw")
    initial = state.mu["Vault.balances"]  # mu is rebound by the later `balances[sender] = 0`
    for node in function.nodes:
        execute_node(machine, state, node)
    amount = z3.Select(initial, environment.sender)
    guard = body_conditions(state, environment)[0]  # require(amount > 0)
    assert not satisfiable(guard, amount == 0)
    assert satisfiable(z3.Not(guard), amount == 0)


def test_condition_of_returns_the_branch_term() -> None:
    """Reentrancy_if guards with `if`, not `require`, so there is a real IF node to branch on."""
    machine, environment, state, function = setup("Reentrancy_if", "withdraw")
    branching = [n for n in function.nodes if n.type is NodeType.IF]
    assert len(branching) == 1
    for node in function.nodes:
        execute_node(machine, state, node)
        if node is branching[0]:
            break  # the node builds the condition and marks it; both happen here

    term = condition_of(machine, state, branching[0])
    assert z3.is_bool(term)
    credit = z3.Select(state.mu["ReentrancyIf.credit"], environment.sender)
    amount = state.rho["amount"]
    assert not satisfiable(term != z3.UGE(credit, amount))

    # The engine forks here; neither branch is in PC yet, and both are reachable.
    assert not state.pc or satisfiable(*state.pc)
    assert satisfiable(*state.pc, term) and satisfiable(*state.pc, z3.Not(term))


# ------------------------------------------------------------------------- trace


def test_the_trace_has_the_shape_phi_re_needs() -> None:
    """read(balances) before the call, lcall, write(balances) after it -- exactly (2.6)."""
    _, _, state = run("Vault", "withdraw")
    kinds = [e.kind for e in state.tau]
    call = kinds.index(EventKind.LCALL)
    assert EventKind.READ in kinds[:call]
    assert EventKind.WRITE in kinds[call:]
    written = [e.variable.name for e in state.tau if e.kind is EventKind.WRITE]
    assert written == ["balances"]


def test_a_low_level_call_carries_r_i_and_may_reenter() -> None:
    """phi_UC (2.7) is lcall_i(a, r_i) AND r_i = false, so r_i must be IN the trace, not only rho."""
    _, environment, state = run("Reentrancy_if", "withdraw")
    calls = [e for e in state.tau if e.kind is EventKind.LCALL]
    assert len(calls) == 1
    call = calls[0]
    assert call.destination is environment.sender
    assert call.value is state.rho["amount"]
    assert call.result is not None and call.result.sort() == z3.BoolSort()
    assert call.can_reenter  # `call` forwards all the gas
    # The callee is unknown code, so both outcomes stay open.
    assert satisfiable(*state.pc, call.result) and satisfiable(*state.pc, z3.Not(call.result))


def test_transfer_moves_value_but_cannot_reenter() -> None:
    """`transfer` buys 2300 gas: not enough for a storage write, so phi_RE must not latch on it."""
    _, _, state = run("Overflow_sub", "withdrawAll")
    calls = [e for e in state.tau if e.kind in (EventKind.CALL, EventKind.LCALL)]
    assert [e.kind for e in calls] == [EventKind.CALL]
    assert not calls[0].can_reenter
    assert calls[0].result is None  # `transfer` reverts on failure instead of returning a flag


def test_an_external_call_returns_a_fresh_symbol() -> None:
    """The callee is unknown code, so its success flag is unconstrained."""
    _, _, state = run("Vault", "withdraw")
    assert satisfiable(*state.pc)


def test_selfdestruct_is_recorded_as_a_privileged_operation() -> None:
    _, _, state = run("Access_unprotected", "kill")
    assert [e.kind for e in state.tau if e.kind is EventKind.PRIV] == [EventKind.PRIV]


# -------------------------------------------------------------------- unsupported


def test_an_internal_call_is_not_guessed_at() -> None:
    """Inlining is the engine's job; until then the path is abandoned rather than mistranslated."""
    with pytest.raises(UnsupportedConstruct):
        run("Mint_internal", "mint")


#: The one fixture function that is deliberately outside the translator, with the reason.
#: Everything else may only stop at an InternalCall, which the engine inlines in week 3.
EXPECTED_UNSUPPORTED = {"Struct_nested.wipeDeep": "holds a mapping"}


def test_every_fixture_translates_except_for_internal_calls() -> None:
    """A regression net: no fixture may fail with anything other than UnsupportedConstruct."""
    from tests.conftest import PINNED

    unsupported: list[str] = []
    for name in PINNED:
        compilation = load(name)
        for contract in compilation.slither.contracts:
            machine = Machine(contract, compilation.checked_arithmetic)
            environment = machine.new_environment()
            for function in list(contract.functions) + list(contract.modifiers):
                if not function.nodes:
                    continue
                state = machine.initial_state(function, environment)
                try:
                    for node in function.nodes:
                        execute_node(machine, state, node)
                except UnsupportedConstruct as error:
                    expected = EXPECTED_UNSUPPORTED.get(f"{name}.{function.name}")
                    if expected is not None and expected in str(error):
                        continue
                    unsupported.append(f"{name}.{function.name}: {error}")
    assert all("InternalCall" in entry for entry in unsupported), unsupported
