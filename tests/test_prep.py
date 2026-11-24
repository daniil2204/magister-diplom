"""Tests for compilation and solc selection."""

from __future__ import annotations

import pytest

from hsa.prep import MAX_SUPPORTED, parse_pragmas, select_version
from tests.conftest import PINNED, load


@pytest.mark.parametrize("name", sorted(PINNED))
def test_every_fixture_compiles(name: str) -> None:
    compilation = load(name)
    assert compilation.slither.contracts, f"{name} produced no contract"


@pytest.mark.parametrize(
    ("name", "checked"),
    [
        ("Vault", True),
        ("Mint_internal", True),
        ("Overflow_mul", False),
        ("Overflow_sub", False),
    ],
)
def test_checked_arithmetic_follows_the_compiler(name: str, checked: bool) -> None:
    """Below 0.8 all arithmetic is unchecked; from 0.8 it is checked outside `unchecked`."""
    assert load(name).checked_arithmetic is checked


def test_parse_pragmas() -> None:
    assert parse_pragmas("pragma solidity ^0.8.0;") == [("^", (0, 8, 0))]
    assert parse_pragmas("pragma solidity 0.4.24;") == [(None, (0, 4, 24))]
    assert parse_pragmas("pragma solidity >=0.5.0 <0.7.0;") == [
        (">=", (0, 5, 0)),
        ("<", (0, 7, 0)),
    ]


def test_select_version_respects_the_caret() -> None:
    """`^0.4.24` must not select 0.5.x: for a 0.x version the caret pins the minor."""
    chosen = select_version("pragma solidity ^0.4.24;")
    assert chosen[:2] == (0, 4)
    assert chosen >= (0, 4, 24)


def test_select_version_respects_a_range() -> None:
    chosen = select_version("pragma solidity >=0.5.0 <0.7.0;")
    assert (0, 5, 0) <= chosen < (0, 7, 0)


def test_select_version_stays_in_the_minor_of_an_open_pragma() -> None:
    """`>=0.5.11` admits 0.8.30, but the file is 0.5-era code and would not compile there."""
    assert select_version("pragma solidity >=0.5.11;") == (0, 5, 17)


def test_an_upper_bound_anywhere_keeps_the_highest_version() -> None:
    """The cap applies to pragmas built only from lower bounds, not to every `>=`."""
    assert select_version("pragma solidity >=0.4.22 <0.9.0;") == MAX_SUPPORTED
