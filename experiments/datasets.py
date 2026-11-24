"""Where the evaluation samples live, and at which commit.

The datasets are kept outside the project directory: solc 0.4.x on Windows cannot handle the
non-ASCII path of the repository, and `prep.py` copies such files one by one into a temporary
ASCII directory. Thousands of copies per run is not worth it, so `D:\\hsa-data` is ASCII.

The commits are recorded here and go into chapter 3: both datasets are moving targets, and a
sample is only reproducible together with the revision it was drawn from.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ROOT = Path("D:/hsa-data")


@dataclass(frozen=True)
class Dataset:
    name: str
    directory: Path
    commit: str
    #: Subdirectory holding the .sol files, one directory per labelled class.
    contracts: Path

    def files(self) -> list[Path]:
        """Every .sol file, in a stable order."""
        return sorted(self.contracts.rglob("*.sol"))


SMARTBUGS = Dataset(
    name="smartbugs-curated",
    directory=ROOT / "smartbugs-curated",
    commit="230e649123477eff332742a59a1c7cc6dc286cab",
    contracts=ROOT / "smartbugs-curated" / "dataset",
)

#: The authors' own repository of the SolidiFI paper, not one of its forks.
SOLIDIFI = Dataset(
    name="SolidiFI-benchmark",
    directory=ROOT / "SolidiFI-benchmark",
    commit="4b0573e1b3f7031396de6f48f7f3e7380222ad3a",
    contracts=ROOT / "SolidiFI-benchmark" / "buggy_contracts",
)

ALL = (SMARTBUGS, SOLIDIFI)
