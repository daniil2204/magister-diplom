"""Tests for the baseline runners of `experiments.baselines` and the resolver in `experiments.units`.

Slither is exercised live (it is a library dependency); Mythril is not installed, so only its pure
parser is tested and `run_mythril` is asserted to fail loudly rather than silently. Both use project
fixtures, so no dataset is required.
"""

from __future__ import annotations

import pytest

from experiments import mapping
from experiments.baselines import (
    BaselineUnavailable,
    _slither_detectors,
    parse_mythril,
    run_mythril,
    run_slither,
)
from experiments.units import function_at
from hsa.prep import compile_contract


# ------------------------------------------------------------------------------ units resolver


def test_function_at_resolves_the_containing_function() -> None:
    compilation = compile_contract("tests/contracts/Vault.sol")
    assert function_at(compilation, 13) == "Vault.withdraw()"
    assert function_at(compilation, 9) == "Vault.deposit()"


def test_function_at_returns_none_outside_any_function() -> None:
    compilation = compile_contract("tests/contracts/Vault.sol")
    assert function_at(compilation, 1) is None  # pragma / contract header


# ----------------------------------------------------------------------------------- Slither


def test_every_mapped_detector_resolves_on_the_installed_slither() -> None:
    assert set(_slither_detectors()) == set(mapping.SLITHER_CLASS)


def test_slither_flags_reentrancy_in_vault() -> None:
    report = run_slither("tests/contracts/Vault.sol", timeout=300.0)
    assert report.error is None
    assert ("SC08", "Vault.withdraw()") in report.units()


def test_slither_does_not_flag_the_cei_fixed_vault() -> None:
    """The CEI fix removes the post-call write, so reentrancy-eth has nothing to report."""
    report = run_slither("tests/contracts/Vault_fixed_cei.sol", timeout=300.0)
    assert report.error is None
    assert not any(swc == "SC08" for swc, _ in report.units())


# ----------------------------------------------------------------------------------- Mythril


def test_mythril_parser_maps_swc_and_drops_unmapped() -> None:
    compilation = compile_contract("tests/contracts/Vault.sol")
    payload = {
        "issues": [
            {"swc-id": "107", "lineno": 13},  # bare number -> SC08
            {"swc-id": "SWC-101", "lineno": 15},  # already prefixed -> SC09
            {"swc-id": "105", "lineno": 13},  # unprotected send -> not mapped
        ]
    }
    findings = parse_mythril(payload, compilation)
    assert {(f.swc, f.function) for f in findings} == {
        ("SC08", "Vault.withdraw()"),
        ("SC09", "Vault.withdraw()"),
    }


def test_mythril_parser_handles_a_missing_line() -> None:
    compilation = compile_contract("tests/contracts/Vault.sol")
    findings = parse_mythril({"issues": [{"swc-id": "107"}]}, compilation)
    assert findings[0].function is None


def test_run_mythril_fails_loudly_when_not_installed() -> None:
    """Mythril is absent in this environment; the runner must say so, not pretend a clean result."""
    with pytest.raises(BaselineUnavailable):
        run_mythril("tests/contracts/Vault.sol", timeout=5.0)
