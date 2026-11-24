"""The real, timed runs on the ~40-contract subsample (chapter 2.3).

The reference run (`experiments/run.py`) measures nothing comparable: it caps every target at 120 s
independently, for the offline lambda / weight replay only. The head-to-head comparison of the four
configurations and the k sweep instead need GENUINE per-contract times under the real budget B_t, so
they are executed here, once, by the online engine (`hsa.cli.analyze`):

* **M1-M4** -- the full method against its three ablations. M3 (no N*_t pruning) and M4 (random queue)
  cannot be replayed from M1: M3 explores different branches (so its verdict AND time change) and M4's
  hypothesis is MEASURED time. Each is a real run here.
* **k1 / k2 / k3** -- loop unrolling changes the verdicts, so the k sweep is re-executed too. (k2 is
  M1; it is run again under its own name so the k curve is a self-contained artefact set.)
* **Slither and Mythril** -- the baselines, at the same per-contract timeout as the method's budget.

Everything runs on `experiments.sample.subsample()` (40 contracts, 10 per SWC class, the experiment
seed), not the whole 147: these runs re-execute the engine and are the expensive part of chapter 2.3.

One analysis per process (`--jobs`), because solc state is process-global and M3's un-pruned search is
memory-heavy; keep `--jobs` at 2 on a 16 GB machine. Each output is written to its own file and a work
item whose file already exists is skipped, so an interrupted run resumes without repeating work.

Usage:

    python -m experiments.timed --out experiments/runs [--jobs 2]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from experiments import baselines, configs
from experiments.sample import Case, subsample
from hsa.cli import analyze
from hsa.config import Config
from hsa.report import write_json


def _hsa_configs() -> dict[str, Config]:
    """The config-driven runs: the four modes, then the k sweep, keyed by output name."""
    runs: dict[str, Config] = {}
    runs.update(configs.modes())
    runs.update(configs.k_sweep())
    return runs


def _destination(out: Path, kind: str, case: Case) -> Path:
    # Mirror run.py's nesting (dataset/label/stem) under a per-run-kind root, so the same stem under
    # several SolidiFI bug-type folders never collides.
    return out / kind / case.dataset / case.label / Path(case.path).stem


def _baseline_json(report: baselines.BaselineReport) -> dict:
    return {
        "tool": report.tool,
        "path": str(report.path),
        "solc_version": report.solc_version,
        "elapsed": round(report.elapsed, 3),
        "timed_out": report.timed_out,
        "error": report.error,
        "findings": [asdict(f) for f in report.findings],
    }


def _run_hsa(name: str, config: Config, case: Case, out: Path) -> dict:
    destination = _destination(out, name, case).with_suffix(".json")
    if destination.exists():
        return {"kind": name, "path": str(case.path), "skipped": True}
    report = analyze(case.path, config)
    write_json(report, destination)
    return {
        "kind": name,
        "path": str(case.path),
        "elapsed": round(report.elapsed, 2),
        "error": report.error,
        "targets": len(report.results),
    }


def _run_baseline(tool: str, case: Case, out: Path, timeout: float) -> dict:
    destination = _destination(out, tool, case).with_suffix(".json")
    if destination.exists():
        return {"kind": tool, "path": str(case.path), "skipped": True}
    runner = baselines.run_slither if tool == "slither" else baselines.run_mythril
    try:
        report = runner(case.path, timeout)
        payload = _baseline_json(report)
        error = report.error
    except baselines.BaselineUnavailable as unavailable:
        payload = {"tool": tool, "path": str(case.path), "error": str(unavailable),
                   "findings": [], "elapsed": 0.0, "timed_out": False, "solc_version": None}
        error = str(unavailable)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"kind": tool, "path": str(case.path), "error": error}


def _run_item(item: tuple) -> dict:
    kind, case, out, extra = item
    if kind in ("slither", "mythril"):
        return _run_baseline(kind, case, out, extra)
    return _run_hsa(kind, extra, case, out)


def _work(sample: list[Case], out: Path, timeout: float) -> list[tuple]:
    items: list[tuple] = []
    hsa = _hsa_configs()
    for case in sample:
        for name, config in hsa.items():
            items.append((name, case, out, config))
        for tool in ("slither", "mythril"):
            items.append((tool, case, out, timeout))
    return items


def run(sample: list[Case], out: Path, jobs: int, timeout: float) -> list[dict]:
    work = _work(sample, out, timeout)
    total = len(work)
    summaries: list[dict] = []
    if jobs <= 1:
        for index, item in enumerate(work):
            summaries.append(_progress(index, total, _run_item(item)))
        return summaries
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(max_workers=jobs) as pool:
        for index, summary in enumerate(pool.map(_run_item, work, chunksize=1)):
            summaries.append(_progress(index, total, summary))
    return summaries


def _progress(index: int, total: int, summary: dict) -> dict:
    if summary.get("skipped"):
        mark = "skip"
    elif summary.get("error"):
        mark = f"ERROR {summary['error']}"
    elif "elapsed" in summary:
        mark = f"{summary['elapsed']}s, {summary['targets']} targets"
    else:
        mark = "done"
    print(f"[{index + 1}/{total}] {summary['kind']:8} {Path(summary['path']).name}: {mark}",
          file=sys.stderr)
    return summary


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("experiments/runs"))
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--limit", type=int, default=None, help="first N subsample contracts")
    arguments = parser.parse_args(argv)

    sample = subsample()
    if arguments.limit:
        sample = sample[: arguments.limit]
    timeout = Config().budget
    summaries = run(sample, arguments.out, arguments.jobs, timeout)

    done = [s for s in summaries if not s.get("skipped")]
    failed = [s for s in summaries if s.get("error")]
    print(
        f"\n{len(sample)} contracts x ({len(_hsa_configs())} configs + 2 baselines) = "
        f"{len(summaries)} items, {len(done)} executed, {len(failed)} errored -> {arguments.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
