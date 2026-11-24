"""Tests for the interprocedural graph.

The b(t) values asserted here are the control values written in the comment of each fixture and
derived by hand from chapter 2. A change in any of them means the thesis text and the fixture
comments have to be re-checked, not the assertion.
"""

from __future__ import annotations

import pytest
from slither.core.declarations import Function
from slither.slithir.operations import Binary, BinaryType

from hsa.icfg import Expansion, entry_points, is_branching
from tests.conftest import load

ARITHMETIC = (BinaryType.ADDITION, BinaryType.SUBTRACTION, BinaryType.MULTIPLICATION)


def function_of(name: str, function_name: str) -> Function:
    contract = load(name).slither.contracts[0]
    return next(f for f in contract.functions if f.name == function_name)


def arithmetic_targets(name: str) -> list[tuple[str, str, int, int, int]]:
    """(entry point, function, node id, depth, b) for every arithmetic operation reached."""
    contract = load(name).slither.contracts[0]
    found = []
    for entry in entry_points(contract):
        expansion = Expansion(entry)
        for vertex in expansion.vertices():
            node = expansion.node(vertex)
            if any(isinstance(ir, Binary) and ir.type in ARITHMETIC for ir in node.irs):
                found.append(
                    (
                        entry.name,
                        node.function.name,
                        node.node_id,
                        vertex.depth,
                        expansion.branch_count(vertex),
                    )
                )
    return sorted(found)


# --------------------------------------------------------------------- entry points


def test_constructor_is_not_an_entry_point() -> None:
    """A constructor cannot be invoked by an attacker, so it generates no targets."""
    contract = load("Owned_ctor").slither.contracts[0]
    assert [f.name for f in entry_points(contract)] == ["setOwner"]


def test_internal_functions_are_not_entry_points() -> None:
    contract = load("Mint_internal").slither.contracts[0]
    assert [f.name for f in entry_points(contract)] == ["mint"]


def test_dead_internal_code_is_unreachable() -> None:
    """_burnDead has no public caller, so no vertex of it exists in any expansion."""
    contract = load("Mint_internal").slither.contracts[0]
    dead = function_of("Mint_internal", "_burnDead")
    for entry in entry_points(contract):
        expansion = Expansion(entry)
        assert not any(expansion.vertices_of(node) for node in dead.nodes)


def test_internal_target_is_reached_from_its_public_caller() -> None:
    """The context of a target in _mint is computed from the entry point mint."""
    expansion = Expansion(function_of("Mint_internal", "mint"))
    inner = function_of("Mint_internal", "_mint")
    assert all(expansion.vertices_of(node) for node in inner.nodes)


# ----------------------------------------------------------------------- modifiers


def test_modifier_guard_dominates_the_body() -> None:
    """The direct edge from the modifier marker to the body must be suppressed.

    Otherwise require(!locked) would not dominate the target and g(t) would be 0 instead of 1.
    """
    withdraw = function_of("Vault_fixed_guard", "withdraw")
    guard = load("Vault_fixed_guard").slither.contracts[0].modifiers[0]
    expansion = Expansion(withdraw)
    target = expansion.vertices_of(withdraw.nodes[6])[0]
    dominators = {expansion.node(v) for v in expansion.dominators(target)}
    assert guard.nodes[1] in dominators  # require(!locked)


def test_modifier_tail_runs_after_the_body() -> None:
    """`locked = false` sits after `_`, so the whole body must precede it."""
    withdraw = function_of("Vault_fixed_guard", "withdraw")
    guard = load("Vault_fixed_guard").slither.contracts[0].modifiers[0]
    expansion = Expansion(withdraw)
    tail = expansion.vertices_of(guard.nodes[4])[0]  # locked = false
    dominators = {expansion.node(v) for v in expansion.dominators(tail)}
    assert withdraw.nodes[6] in dominators  # balances[msg.sender] = 0


def test_modifier_frames_do_not_consume_inlining_depth() -> None:
    """Modifiers are always inlined, whatever d is."""
    withdraw = function_of("Vault_fixed_guard", "withdraw")
    expansion = Expansion(withdraw)
    assert expansion.vertices_of(withdraw.nodes[6])[0].depth == 0


# ----------------------------------------------------------------------------- b(t)


def test_require_counts_towards_b() -> None:
    """Slither models require as an EXPRESSION node, so it has to be counted explicitly."""
    withdraw = function_of("Vault", "withdraw")
    assert is_branching(withdraw.nodes[2])  # require(amount > 0)
    assert is_branching(withdraw.nodes[5])  # require(ok)


def test_vault_reentrancy_branch_count() -> None:
    """Control value: b = 2 for the RE target of Vault.withdraw."""
    withdraw = function_of("Vault", "withdraw")
    expansion = Expansion(withdraw)
    target = expansion.vertices_of(withdraw.nodes[6])[0]  # balances[msg.sender] = 0
    assert expansion.branch_count(target) == 2


def test_guarded_vault_branch_count() -> None:
    """Control value: b = 3 for both RE targets of Vault_fixed_guard."""
    withdraw = function_of("Vault_fixed_guard", "withdraw")
    guard = load("Vault_fixed_guard").slither.contracts[0].modifiers[0]
    expansion = Expansion(withdraw)
    for node in (withdraw.nodes[6], guard.nodes[4]):
        target = expansion.vertices_of(node)[0]
        assert expansion.branch_count(target) == 3, node


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        # (entry point, function, node id, depth, b) -- see the comment in each fixture.
        ("Overflow_mul", [("batch2", "batch2", 1, 0, 0), ("batch2", "batch2", 3, 0, 1),
                          ("batch2", "batch2", 4, 0, 1), ("batch2", "batch2", 5, 0, 1)]),
        ("Overflow_sub", [("withdrawAll", "withdrawAll", 1, 0, 0)]),
        ("Overflow_transfer", [("transfer", "transfer", 2, 0, 1),
                               ("transfer", "transfer", 3, 0, 1)]),
        ("Overflow_guarded", [("burn", "burn", 2, 0, 1)]),
        ("Overflow_args", [("mulArgs", "mulArgs", 1, 0, 0),
                           ("mulOwner", "mulOwner", 1, 0, 1)]),
        ("Mint_internal", [("mint", "_mint", 1, 1, 1), ("mint", "_mint", 2, 1, 1)]),
    ],
)
def test_arithmetic_control_values(name: str, expected: list[tuple]) -> None:
    assert arithmetic_targets(name) == sorted(expected)
