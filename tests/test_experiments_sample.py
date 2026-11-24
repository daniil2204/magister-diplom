"""Tests for the experimental sample of `experiments.sample` (chapter 2.3, variant A).

These do not need the datasets cloned: they are skipped when `D:\\hsa-data` is absent, so the suite
still runs on a machine without the samples. Where the datasets are present they pin the shape of
variant A -- 112 + 35 = 147 -- and the determinism of the SolidiFI draw.
"""

from __future__ import annotations

import pytest

from experiments import mapping, sample
from experiments.datasets import SMARTBUGS, SOLIDIFI

_HAVE_DATASETS = SMARTBUGS.contracts.is_dir() and SOLIDIFI.contracts.is_dir()
pytestmark = pytest.mark.skipif(not _HAVE_DATASETS, reason="datasets not cloned under D:/hsa-data")


def test_the_sample_is_147_contracts() -> None:
    assert len(sample.cases()) == 147


def test_smartbugs_takes_every_compilable_category_contract() -> None:
    smartbugs = [c for c in sample.cases() if c.dataset == SMARTBUGS.name]
    per_category = {cat: 0 for cat in mapping.SMARTBUGS_SAMPLED_CATEGORIES}
    for case in smartbugs:
        per_category[case.label] += 1
    assert per_category == {
        "access_control": 17,
        "arithmetic": 15,
        "reentrancy": 29,
        "unchecked_low_level_calls": 51,
    }


def test_solidifi_draws_seven_per_type() -> None:
    solidifi = [c for c in sample.cases() if c.dataset == SOLIDIFI.name]
    per_type = {t: 0 for t in mapping.SOLIDIFI_SAMPLED_TYPES}
    for case in solidifi:
        per_type[case.label] += 1
    assert set(per_type.values()) == {sample.SOLIDIFI_PER_TYPE}
    assert len(per_type) == 5


def test_excluded_contracts_are_absent() -> None:
    paths = {c.path.as_posix() for c in sample.cases()}
    for relative in sample.EXCLUDED[SMARTBUGS.name]:
        assert (SMARTBUGS.contracts / relative).as_posix() not in paths


def test_every_case_carries_the_right_swc() -> None:
    for case in sample.cases():
        expected = (
            mapping.smartbugs_swc(case.label)
            if case.dataset == SMARTBUGS.name
            else mapping.solidifi_swc(case.label)
        )
        assert case.swc == expected


def test_the_solidifi_draw_is_deterministic() -> None:
    """Same seed, same draw -- the sample must be reproducible from the one number."""
    first = [c.path for c in sample.solidifi_cases()]
    second = [c.path for c in sample.solidifi_cases()]
    assert first == second


def test_the_sample_matches_the_measurement_run() -> None:
    assert sample.verify() == []
