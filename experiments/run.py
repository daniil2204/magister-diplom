"""The reference run: every target of the sample, each under the same large per-target cap.

Chapter 2.3 splits the measurement in two, because lambda and the weights change both the queue order
AND the budget B_t (2.18), so they cannot be swept by re-running the engine once:

* this **reference run** gives every target its own `reference_cap` seconds (120 s by default), with no
  shared budget and no skipping, and records the verdict and the time it took to reach it. It is for
  modelling only and is NOT one of the timed M1 runs;
* `experiments/metrics.py` then **replays** each (lambda, alpha, beta, gamma): it recomputes the queue
  and B_t and declares a target CONFIRMED / REFUTED only if its reference time to verdict fits inside
  the B_t it would have been granted, carrying unused time forward exactly as `analyze_targets` does.

Two artefacts are written per contract, into `--out`:

* `<dataset>/<stem>.json` -- the reference `ContractReport`, same schema as `hsa.cli`;
* `<dataset>/<stem>.static.pkl` -- the config-independent facts the replay needs (A, D, M, S, b per
  target). This is the pickle cache chapter 2.3 asks for: the static stage is the same for every
  configuration, so it is computed once here and re-read by the replay instead of recompiling. Slither
  objects do not pickle, so only the plain `StaticTarget` numbers are stored, joined back to the report
  by `target_id`.

Contracts are analysed one per process (`--jobs`), because one Slither analysis per contract is the
unit of work and solc state is process-global.

Usage:

    python -m experiments.run --out experiments/runs/reference [--jobs 8] [--limit N]
"""

from __future__ import annotations

import argparse
import pickle
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from experiments.configs import BASE
from experiments.sample import Case, cases
from hsa.cli import analysed_contracts
from hsa.config import Config
from hsa.prep import compile_contract
from hsa.priority import controllability, exposure, priority, risk, value_factor
from hsa.report import ContractReport, write_json
from hsa.static import DETECTORS
from hsa.static.base import Analysis
from hsa.symexec.engine import _run_target
from hsa.model import Target, TargetResult


def target_id(target: Target) -> str:
    """A stable identity joining a report target to its `StaticTarget`.

    (class, entry point, containing function, node, operation index) -- the full target tuple of
    (2.13) plus the entry point, so that a node reached from several entry points, several targets on
    one node (e.g. two OV operations), and AC vs TO on the same operation all stay distinct. Every
    part is reconstructable from the report JSON (`class`, `entry_point`, `function`, `node_id`,
    `op_index`), so `metrics.py` can rebuild the same key without the Target object.
    """
    point = target.point
    return "|".join(
        (
            target.vuln_class.name,
            target.entry_point.canonical_name,
            target.function.canonical_name,
            str(point.node.node_id),
            str(point.op_index),
        )
    )


@dataclass(frozen=True)
class StaticTarget:
    """Config-independent facts about one target: enough to replay R and P (2.14-2.18) off-line.

    A, D, M and S are stored rather than R and P, because R = S*(alpha*A + beta*D + gamma*M) cannot be
    decomposed back into its components, and the weight sweep needs each component on its own.
    """

    target_id: str
    controllability: float  # A(t)
    exposure: float  # D(t)
    value_factor: float  # M(t)
    severity: float  # S(v)
    branch_count: int  # b(t)


def _static_target(target: Target, config: Config) -> StaticTarget:
    return StaticTarget(
        target_id=target_id(target),
        controllability=controllability(target),
        exposure=exposure(target),
        value_factor=value_factor(target),
        severity=config.severity_of(target.vuln_class),
        branch_count=target.branch_count,
    )


@dataclass(frozen=True)
class StaticCache:
    """The sidecar pickle: the static stage, config-independent, for the offline replay.

    `static_elapsed` is kept here rather than in the report JSON so the fixed report schema is not
    touched. The replay needs it because Recall(tau) counts from the start of the contract analysis
    (chapter 2.3), which includes the static stage, not from the first symbolic target.
    """

    static_elapsed: float
    targets: list[dict]  # asdict(StaticTarget)


def reference_report(
    case: Case, config: Config
) -> tuple[ContractReport, StaticCache]:
    """Analyse one contract: every target independently at `config.reference_cap`.

    Independent means no shared budget and no `skipped_confirmed`: the replay models both of those
    from the per-target times, so the reference run must give a genuine verdict and time to EVERY
    target. `time_to_verdict` is therefore the target's own solve time, not a cumulative queue time.
    """
    started = time.perf_counter()
    try:
        compilation = compile_contract(case.path)
    except Exception as error:  # noqa: BLE001 - a bad file is a data point, not a crash
        report = ContractReport(
            path=case.path,
            config=config,
            elapsed=time.perf_counter() - started,
            error=f"{type(error).__name__}: {error}",
        )
        return report, StaticCache(static_elapsed=time.perf_counter() - started, targets=[])

    pairs = [
        (analysis, target)
        for contract in analysed_contracts(compilation.slither)
        for analysis in [Analysis.build(compilation, contract)]
        for detector in DETECTORS
        for target in detector.detect(analysis)
    ]
    static_elapsed = time.perf_counter() - started

    results: list[TargetResult] = []
    statics: list[StaticTarget] = []
    for analysis, target in pairs:
        outcome, elapsed = _run_target(analysis, target, config, config.reference_cap)
        results.append(
            TargetResult(
                target=target,
                verdict=outcome.verdict,
                risk=risk(target, config),
                priority=priority(target, config),
                budget=config.reference_cap,
                elapsed=elapsed,
                time_to_verdict=elapsed,
                reason=outcome.reason,
                counterexample=outcome.counterexample,
            )
        )
        statics.append(_static_target(target, config))

    report = ContractReport(
        path=case.path,
        config=config,
        solc_version=compilation.solc_version,
        results=results,
        elapsed=time.perf_counter() - started,
    )
    cache = StaticCache(static_elapsed=static_elapsed, targets=[asdict(s) for s in statics])
    return report, cache


def _destination(out: Path, case: Case) -> Path:
    # Nest by the dataset's own subdirectory (`label`), not the stem alone: SolidiFI lays the same
    # stem (e.g. buggy_33) under several bug-type folders, so `dataset/stem` would silently overwrite
    # distinct contracts. `label` is exactly that subdirectory (see `experiments.sample`).
    return out / case.dataset / case.label / Path(case.path).stem


def run_case(case: Case, config: Config, out: Path) -> dict:
    """Analyse one case and write both artefacts. Returns a short summary for the driver."""
    report, cache = reference_report(case, config)
    base = _destination(out, case)
    write_json(report, base.with_suffix(".json"))
    base.with_suffix(".static.pkl").write_bytes(pickle.dumps(asdict(cache)))
    return {
        "path": str(case.path),
        "targets": len(report.results),
        "error": report.error,
        "elapsed": round(report.elapsed, 2),
    }


def _run_one(argument: tuple[Case, Config, Path]) -> dict:
    return run_case(*argument)


def run(sample: list[Case], config: Config, out: Path, jobs: int) -> list[dict]:
    work = [(case, config, out) for case in sample]
    if jobs <= 1:
        return [_progress(index, len(work), _run_one(item)) for index, item in enumerate(work)]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        summaries = []
        for index, summary in enumerate(pool.map(_run_one, work, chunksize=1)):
            summaries.append(_progress(index, len(work), summary))
        return summaries


def _progress(index: int, total: int, summary: dict) -> dict:
    mark = f"ERROR {summary['error']}" if summary["error"] else f"{summary['targets']} targets"
    print(f"[{index + 1}/{total}] {Path(summary['path']).name}: {mark}", file=sys.stderr)
    return summary


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("experiments/runs/reference"))
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--limit", type=int, default=None, help="first N contracts of the sample")
    arguments = parser.parse_args(argv)

    sample = cases()
    if arguments.limit:
        sample = sample[: arguments.limit]
    summaries = run(sample, BASE, arguments.out, arguments.jobs)

    failed = [s for s in summaries if s["error"]]
    total_targets = sum(s["targets"] for s in summaries)
    print(
        f"\n{len(summaries)} contracts, {total_targets} targets, {len(failed)} failed"
        f" -> {arguments.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
