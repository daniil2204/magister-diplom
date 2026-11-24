"""Tests for the reference run of `experiments.run`.

These use a project fixture, not the datasets, so the suite runs without `D:\\hsa-data`. They pin the
two things the replay in `metrics.py` relies on: the reference run issues an independent verdict and
time per target (`time_to_verdict == elapsed`), and the report and the static pickle share a
`target_id` that is reconstructable from the JSON alone.
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

from experiments.configs import BASE
from experiments.run import _destination, reference_report, run_case, target_id
from experiments.sample import Case

VAULT = Case("tests", Path("tests/contracts/Vault.sol"), "reentrancy", "SC08")


def _id_from_json(entry: dict) -> str:
    """The same key `target_id` builds, reconstructed from a report target -- the join `metrics` does."""
    return "|".join(
        (
            entry["class"],
            entry["entry_point"],
            entry["function"],
            str(entry["node_id"]),
            str(entry["op_index"]),
        )
    )


def test_vault_reference_run_confirms_the_single_re_target() -> None:
    report, cache = reference_report(VAULT, BASE)
    assert report.error is None
    assert [r.verdict.value for r in report.results] == ["CONFIRMED"]
    assert [r.target.vuln_class.name for r in report.results] == ["RE"]
    assert len(cache.targets) == 1
    assert cache.static_elapsed > 0.0


def test_time_to_verdict_is_the_targets_own_time() -> None:
    """Reference timing is independent: the replay builds the cumulative timeline itself."""
    report, _ = reference_report(VAULT, BASE)
    for result in report.results:
        assert result.time_to_verdict == result.elapsed
        assert result.budget == BASE.reference_cap


def test_static_components_match_the_control_values() -> None:
    _, cache = reference_report(VAULT, BASE)
    static = cache.targets[0]
    assert static["controllability"] == 0.5
    assert static["exposure"] == 1.0
    assert static["value_factor"] == 1.0
    assert static["severity"] == 1.0
    assert static["branch_count"] == 2


def test_run_case_writes_both_artefacts_that_join_by_id(tmp_path: Path) -> None:
    summary = run_case(VAULT, BASE, tmp_path)
    assert summary["error"] is None
    assert summary["targets"] == 1

    report_path = tmp_path / "tests" / "reentrancy" / "Vault.json"
    static_path = tmp_path / "tests" / "reentrancy" / "Vault.static.pkl"
    assert report_path.is_file() and static_path.is_file()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    cache = pickle.loads(static_path.read_bytes())
    report_ids = {_id_from_json(t) for t in report["targets"]}
    static_ids = {s["target_id"] for s in cache["targets"]}
    assert report_ids == static_ids


def test_op_index_is_in_the_report_schema(tmp_path: Path) -> None:
    run_case(VAULT, BASE, tmp_path)
    report = json.loads((tmp_path / "tests" / "reentrancy" / "Vault.json").read_text(encoding="utf-8"))
    assert all("op_index" in target for target in report["targets"])


def test_destination_disambiguates_colliding_stems_across_subdirs(tmp_path: Path) -> None:
    """SolidiFI repeats a stem (buggy_33) across bug-type folders; the artefact path must stay unique."""
    overflow = Case("SolidiFI-benchmark", Path("x/Overflow-Underflow/buggy_33.sol"),
                    "Overflow-Underflow", "SC09")
    unchecked = Case("SolidiFI-benchmark", Path("y/Unchecked-Send/buggy_33.sol"),
                     "Unchecked-Send", "SC06")
    assert _destination(tmp_path, overflow) != _destination(tmp_path, unchecked)
