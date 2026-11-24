"""Tests for the JSON report and the CLI.

The JSON schema is what chapter 3 is built from, so the fields `contract` (original path),
`solc_version` and `entry_point` are asserted explicitly: losing any of them makes a run
irreproducible or makes `metrics.py` merge targets that must stay apart.
"""

from __future__ import annotations

import json

import pytest

from hsa.cli import analyze, main
from hsa.config import Config, Mode
from hsa.model import UnknownReason, Verdict
from hsa.report import write_json
from tests.conftest import CONTRACTS, PINNED

M2 = Config(mode=Mode.M2)


def report_of(name: str):
    return analyze(CONTRACTS / f"{name}.sol", M2, PINNED[name])


def test_report_keeps_the_original_non_ascii_path() -> None:
    """solc 0.4.x is given an ASCII copy; the report must still name the real file."""
    report = report_of("Overflow_sub")
    assert report.path == CONTRACTS / "Overflow_sub.sol"
    assert report.to_json()["contract"] == str(CONTRACTS / "Overflow_sub.sol")


def test_report_records_the_version_actually_used() -> None:
    assert report_of("Overflow_sub").to_json()["solc_version"] == "0.4.24"
    assert report_of("Vault").to_json()["solc_version"] == "0.8.20"


def test_every_target_carries_its_entry_point() -> None:
    """Targets sharing a node but differing in entry point must stay distinguishable."""
    targets = report_of("Mint_internal").to_json()["targets"]
    assert targets
    for target in targets:
        assert target["entry_point"] == "MintInternal.mint(address,uint256)"
        assert target["function"] == "MintInternal._mint(address,uint256)"


def test_targets_are_written_in_queue_order() -> None:
    """The JSON must replay the priority queue, not the detector order."""
    targets = report_of("Overflow_mul").to_json()["targets"]
    assert [t["P"] for t in targets] == sorted((t["P"] for t in targets), reverse=True)


def test_m2_marks_every_target_static_only() -> None:
    """M2 has no symbolic stage: every target is UNKNOWN, which moderate counts as a positive.

    The reason must be present. `reason: null` would make a run without symbolic execution
    indistinguishable from a bug that dropped the reason.
    """
    report = report_of("Vault")
    assert [r.verdict for r in report.results] == [Verdict.UNKNOWN]
    assert [r.reason for r in report.results] == [UnknownReason.STATIC_ONLY]
    assert report.to_json()["targets"][0]["reason"] == "static_only"


def test_no_unknown_is_ever_left_without_a_reason() -> None:
    for name in ("Overflow_mul", "Tx_origin", "Delegatecall_proxy"):
        for result in report_of(name).results:
            assert result.verdict is not Verdict.UNKNOWN or result.reason is not None


def test_units_aggregate_the_targets() -> None:
    units = report_of("Tx_origin").to_json()["units"]
    assert {(u["swc"], u["verdict"]) for u in units} == {("SC01", "UNKNOWN")}
    assert {u["function"] for u in units} == {
        "TxOrigin.setOwnerOrigin(address)",
        "TxOrigin.setOwnerSender(address)",
    }


def test_contract_without_targets_reports_none() -> None:
    report = report_of("Vault_fixed_cei")
    assert report.results == []
    assert report.to_json()["targets"] == []
    assert "no targets" in report.text()


def test_budget_is_distributed_over_the_queue() -> None:
    report = report_of("Overflow_mul")
    assert sum(r.budget for r in report.results) == pytest.approx(M2.budget)


def test_a_broken_source_becomes_an_error_not_an_exception(tmp_path) -> None:
    """A dataset run must survive a file that does not compile."""
    broken = tmp_path / "Broken.sol"
    broken.write_text("pragma solidity ^0.8.0; contract B { function f() {} }", encoding="utf-8")
    report = analyze(broken, M2)
    assert report.error is not None
    assert report.results == []
    assert report.solc_version is None
    assert "ERROR" in report.text()


def test_json_round_trips(tmp_path) -> None:
    destination = tmp_path / "nested" / "result.json"
    write_json(report_of("Vault"), destination)
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["config"]["mode"] == "M2"
    assert data["config"]["lambda"] == 0.5
    assert data["targets"][0]["class"] == "RE"
    assert data["targets"][0]["swc"] == "SC08"


def test_cli_writes_a_report(tmp_path, capsys) -> None:
    destination = tmp_path / "out.json"
    code = main(
        ["analyze", str(CONTRACTS / "Vault.sol"), "--config", "M2", "--out", str(destination)]
    )
    assert code == 0
    assert "RE" in capsys.readouterr().out
    assert json.loads(destination.read_text(encoding="utf-8"))["contract"].endswith("Vault.sol")


def test_cli_runs_the_symbolic_stage_under_m1() -> None:
    """M1 now runs symbolic execution: an unguarded underflow is CONFIRMED, not a static warning."""
    report = analyze(CONTRACTS / "Overflow_sub.sol", Config(mode=Mode.M1), PINNED["Overflow_sub"])
    assert [r.verdict for r in report.results] == [Verdict.CONFIRMED]
    assert report.results[0].reason is None
    assert report.results[0].counterexample is not None


def test_cli_exit_code_is_zero_for_every_configuration() -> None:
    for mode in ("M1", "M2", "M3", "M4"):
        assert main(["analyze", str(CONTRACTS / "Vault.sol"), "--config", mode]) == 0
