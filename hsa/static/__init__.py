"""Static stage: turn a contract into the target set T.

The static stage never issues a verdict. Detectors are listed in a fixed order so that the target
set is deterministic before the priority queue reorders it.
"""

from __future__ import annotations

from slither.core.declarations import Contract

from hsa.model import Target
from hsa.prep import Compilation
from hsa.static.access_control import AccessControlDetector
from hsa.static.base import Analysis, Detector
from hsa.static.delegatecall import DelegatecallDetector
from hsa.static.overflow import OverflowDetector
from hsa.static.reentrancy import ReentrancyDetector
from hsa.static.unchecked_call import UncheckedCallDetector

DETECTORS: tuple[Detector, ...] = (
    ReentrancyDetector(),
    UncheckedCallDetector(),
    AccessControlDetector(),
    DelegatecallDetector(),
    OverflowDetector(),
)


def detect(compilation: Compilation, contract: Contract) -> list[Target]:
    """Every target of one contract, in detector order."""
    analysis = Analysis.build(compilation, contract)
    targets: list[Target] = []
    for detector in DETECTORS:
        targets.extend(detector.detect(analysis))
    return targets


__all__ = [
    "Analysis",
    "DETECTORS",
    "Detector",
    "AccessControlDetector",
    "DelegatecallDetector",
    "OverflowDetector",
    "ReentrancyDetector",
    "UncheckedCallDetector",
    "detect",
]
