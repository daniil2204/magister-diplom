"""JSON and text reports.

Everything in chapter 3 is built from these JSON files, so the schema is fixed here and nowhere
else. Two fields are load-bearing and easy to lose:

* `contract` is always the **original** path, never the temporary ASCII copy `prep.py` hands to
  solc on a non-ASCII project directory;
* `entry_point` is written for every target, because targets that share a node but differ in
  entry point are otherwise indistinguishable and `metrics.py` cannot aggregate them.

`solc_version` is the version actually used, not the pragma, so a run can be reproduced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from hsa.config import Config, VulnClass
from hsa.model import TargetResult, Verdict, aggregate


def version_text(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def config_to_json(config: Config) -> dict[str, Any]:
    """The parameters a run depends on. The sensitivity analysis varies all of them."""
    return {
        "mode": config.mode.value,
        "alpha": config.alpha,
        "beta": config.beta,
        "gamma": config.gamma,
        "lambda": config.lam,
        "severity": {v.name: config.severity_of(v) for v in VulnClass},
        "k_unroll": config.k_unroll,
        "d_inline": config.d_inline,
        "budget": config.budget,
        "b_min": config.b_min,
        "ov_strong_fraction": config.ov_strong_fraction,
        "ov_strong_min": config.ov_strong_min,
        "ov_strong_max": config.ov_strong_max,
        "seed": config.seed,
    }


@dataclass
class ContractReport:
    """The result of analysing one contract file under one configuration."""

    path: Path  # the original source path, even when solc saw a copy
    config: Config
    solc_version: Optional[tuple[int, int, int]] = None
    results: list[TargetResult] = field(default_factory=list)
    elapsed: float = 0.0  # wall clock seconds for the whole contract
    #: Set when the contract could not be analysed at all (compilation failure, unsupported
    #: version). A contract that fails here contributes zero targets, never a crash.
    error: Optional[str] = None

    @property
    def units(self) -> dict[tuple[str, str], Verdict]:
        """Evaluation units (SWC class, function containing the node)."""
        return aggregate(self.results)

    def counts(self) -> dict[str, int]:
        """Targets per verdict, for the text report."""
        counts = {verdict.value: 0 for verdict in Verdict}
        for result in self.results:
            counts[result.verdict.value] += 1
        return counts

    def to_json(self) -> dict[str, Any]:
        return {
            "contract": str(self.path),
            "solc_version": version_text(self.solc_version) if self.solc_version else None,
            "config": config_to_json(self.config),
            "elapsed": round(self.elapsed, 3),
            "error": self.error,
            "targets": [result.to_json() for result in self.results],
            "units": [
                {"swc": swc, "function": function, "verdict": verdict.value}
                for (swc, function), verdict in sorted(self.units.items())
            ],
        }

    def text(self) -> str:
        """Human-readable summary. Claims nothing the JSON does not contain."""
        lines = [
            f"{self.path}",
            f"  solc {version_text(self.solc_version) if self.solc_version else '-'}"
            f"  config {self.config.mode.value}"
            f"  {self.elapsed:.2f}s",
        ]
        if self.error:
            lines.append(f"  ERROR {self.error}")
            return "\n".join(lines)
        if not self.results:
            lines.append("  no targets")
            return "\n".join(lines)
        counts = self.counts()
        lines.append(
            "  targets {}: {}".format(
                len(self.results),
                ", ".join(f"{name} {counts[name]}" for name in counts if counts[name]),
            )
        )
        for result in self.results:
            target = result.target
            line = result.to_json()["line"]
            reason = f" ({result.reason.value})" if result.reason else ""
            lines.append(
                f"  {target.vuln_class.name:<2} {result.verdict.value:<9}{reason}"
                f" {target.function.canonical_name}:{line}"
                f" via {target.entry_point.name}"
                f"  R={result.risk:.3f} P={result.priority:.3f} b={target.branch_count}"
            )
        lines.append("  units:")
        for (swc, function), verdict in sorted(self.units.items()):
            lines.append(f"    {swc} {function} -> {verdict.value}")
        return "\n".join(lines)


def write_json(report: ContractReport, path: str | Path) -> None:
    """Write the JSON report. `ensure_ascii=False` keeps non-ASCII paths readable."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report.to_json(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
