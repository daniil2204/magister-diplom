"""Shared fixtures.

The solc version is pinned per contract rather than resolved from the pragma, so that a new
release of solc cannot silently change a control value.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hsa.prep import Compilation, compile_contract

CONTRACTS = Path(__file__).parent / "contracts"

#: Pinned compiler per fixture. `^0.8.0` fixtures are built with 0.8.20, as their comments say.
PINNED: dict[str, tuple[int, int, int]] = {
    "Vault": (0, 8, 20),
    "Vault_fixed_cei": (0, 8, 20),
    "Vault_fixed_guard": (0, 8, 20),
    "Owned_ctor": (0, 8, 20),
    "Mint_internal": (0, 8, 20),
    "Modular": (0, 8, 20),
    "Unchecked_call": (0, 8, 20),
    "Access_unprotected": (0, 8, 20),
    "Tx_origin": (0, 8, 20),
    "Delegatecall_proxy": (0, 8, 20),
    "Reentrancy_if": (0, 8, 20),
    "Reentrancy_cross": (0, 8, 20),
    "Struct_bank": (0, 8, 20),
    "Struct_nested": (0, 8, 20),
    "SimpleDAO_orig": (0, 4, 24),
    "Overflow_mul": (0, 4, 24),
    "Overflow_loop": (0, 4, 24),
    "Overflow_sub": (0, 4, 24),
    "Overflow_transfer": (0, 4, 24),
    "Overflow_guarded": (0, 4, 24),
    "Overflow_args": (0, 4, 24),
    "Safemath_internal": (0, 4, 24),
    "Name_collision": (0, 4, 24),
    "Recursive_sum": (0, 4, 24),
    "Safemath_library": (0, 4, 24),
    "Library_public": (0, 4, 24),
}

_cache: dict[str, Compilation] = {}


def load(name: str) -> Compilation:
    """Compile a fixture once per session."""
    if name not in _cache:
        _cache[name] = compile_contract(CONTRACTS / f"{name}.sol", PINNED[name])
    return _cache[name]


@pytest.fixture(scope="session")
def contracts() -> dict[str, Compilation]:
    return {name: load(name) for name in PINNED}
