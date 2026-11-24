"""Mapping of dataset labels and baseline-tool findings onto the five method classes.

The method scores six classes (table 2.3) but reports under five SWC codes -- SC01, SC06, SC08,
SC09, SC10 -- because AC and TO share SC01. Chapter 3 compares three different sources against each
other on those codes, and each names its findings differently, so every source needs one map here:

* the dataset labels: SmartBugs Curated tags a file by `category`, SolidiFI by the directory it
  injected the bug into. Only the categories the method covers are mapped; `time_manipulation`,
  `front_running` and the rest return None and are dropped from the evaluation (chapter 2.3,
  "розмітку інших класів ігноруємо");
* the baselines: Slither reports a detector check, Mythril an SWC id. The two maps follow the table
  in CLAUDE.md exactly; `arbitrary-send-eth` / SWC-105 are deliberately left out, because an
  unprotected ether send is not in the method's Priv set and so is not one of the five classes.

Every target value is a method SWC code, checked against `hsa.config` so a typo here cannot invent a
class the method does not report.
"""

from __future__ import annotations

from typing import Optional

from hsa.config import VulnClass

#: The five SWC codes the method reports under. Any value produced by a map below must be one of
#: these, or the maps and the method have drifted apart.
METHOD_SWC = frozenset(v.swc for v in VulnClass)


# ------------------------------------------------------------------- dataset labels

#: SmartBugs Curated `category` -> SWC. Only the four categories chapter 2.3 samples are here; every
#: other category maps to None and its contracts carry no ground-truth unit.
SMARTBUGS_CLASS: dict[str, str] = {
    "access_control": "SC01",
    "arithmetic": "SC09",
    "reentrancy": "SC08",
    "unchecked_low_level_calls": "SC06",
}

#: SolidiFI bug type (the injection directory name) -> SWC. Five types are sampled; `Unchecked-Send`
#: and `Unhandled-Exceptions` both map to SC06 (both are the unchecked-call class). `TOD` and
#: `Timestamp-Dependency` are outside the method's classes and map to None.
SOLIDIFI_CLASS: dict[str, str] = {
    "Overflow-Underflow": "SC09",
    "Re-entrancy": "SC08",
    "Unchecked-Send": "SC06",
    "Unhandled-Exceptions": "SC06",
    "tx.origin": "SC01",
}

#: The SmartBugs categories drawn into the sample (chapter 2.3, variant A).
SMARTBUGS_SAMPLED_CATEGORIES: tuple[str, ...] = tuple(SMARTBUGS_CLASS)

#: The SolidiFI bug types drawn into the sample: five types, seven contracts each.
SOLIDIFI_SAMPLED_TYPES: tuple[str, ...] = tuple(SOLIDIFI_CLASS)


# --------------------------------------------------------------------- baselines

#: Slither detector check -> SWC (CLAUDE.md table; names verified against the installed
#: slither-analyzer via `slither --list-detectors`). Slither ships no SC09 detector, so its SC09
#: recall is zero by construction -- a fact chapter 3 notes under the table rather than a failure.
SLITHER_CLASS: dict[str, str] = {
    "reentrancy-eth": "SC08",
    "reentrancy-no-eth": "SC08",
    "unchecked-lowlevel": "SC06",
    "unchecked-send": "SC06",
    "suicidal": "SC01",
    "unprotected-upgrade": "SC01",
    "tx-origin": "SC01",
    "controlled-delegatecall": "SC10",
}

#: Mythril SWC id -> method SWC (CLAUDE.md table). SWC-106 (selfdestruct) and SWC-115 (tx.origin)
#: both fall under the method's SC01.
MYTHRIL_CLASS: dict[str, str] = {
    "SWC-107": "SC08",
    "SWC-104": "SC06",
    "SWC-106": "SC01",
    "SWC-115": "SC01",
    "SWC-112": "SC10",
    "SWC-101": "SC09",
}


def smartbugs_swc(category: str) -> Optional[str]:
    """SWC of a SmartBugs category, or None if the method does not cover it."""
    return SMARTBUGS_CLASS.get(category)


def solidifi_swc(bug_type: str) -> Optional[str]:
    """SWC of a SolidiFI bug type, or None if the method does not cover it."""
    return SOLIDIFI_CLASS.get(bug_type)


def slither_swc(check: str) -> Optional[str]:
    """SWC of a Slither detector check, or None if it is not one of the mapped detectors."""
    return SLITHER_CLASS.get(check)


def mythril_swc(swc_id: str) -> Optional[str]:
    """SWC of a Mythril finding id (e.g. `SWC-107`), or None if it is not mapped."""
    return MYTHRIL_CLASS.get(swc_id)
