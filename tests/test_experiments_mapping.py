"""Tests for the label/baseline -> SWC maps of `experiments.mapping`.

These pin two things: every map lands on one of the method's five SWC codes (a typo cannot invent a
class), and the two deliberate omissions -- `arbitrary-send-eth` / SWC-105 -- stay out, because an
unprotected ether send is not in the method's Priv set.
"""

from __future__ import annotations

from experiments import mapping


def test_every_mapped_value_is_a_method_swc() -> None:
    """No map may name a class the method does not report under."""
    for table in (
        mapping.SMARTBUGS_CLASS,
        mapping.SOLIDIFI_CLASS,
        mapping.SLITHER_CLASS,
        mapping.MYTHRIL_CLASS,
    ):
        assert set(table.values()) <= mapping.METHOD_SWC, table


def test_method_swc_is_the_five_reported_codes() -> None:
    assert mapping.METHOD_SWC == {"SC01", "SC06", "SC08", "SC09", "SC10"}


def test_smartbugs_covers_only_the_four_sampled_categories() -> None:
    assert set(mapping.SMARTBUGS_CLASS) == {
        "access_control",
        "arithmetic",
        "reentrancy",
        "unchecked_low_level_calls",
    }
    assert mapping.SMARTBUGS_SAMPLED_CATEGORIES == tuple(mapping.SMARTBUGS_CLASS)


def test_solidifi_covers_the_five_sampled_types() -> None:
    assert set(mapping.SOLIDIFI_CLASS) == {
        "Overflow-Underflow",
        "Re-entrancy",
        "Unchecked-Send",
        "Unhandled-Exceptions",
        "tx.origin",
    }
    assert mapping.SOLIDIFI_SAMPLED_TYPES == tuple(mapping.SOLIDIFI_CLASS)


def test_the_two_unchecked_solidifi_types_both_map_to_sc06() -> None:
    """Five types, four classes: `Unchecked-Send` and `Unhandled-Exceptions` are both SC06."""
    assert mapping.SOLIDIFI_CLASS["Unchecked-Send"] == "SC06"
    assert mapping.SOLIDIFI_CLASS["Unhandled-Exceptions"] == "SC06"


def test_unmapped_dataset_labels_return_none() -> None:
    """Categories outside the method's classes are dropped, not misclassified."""
    assert mapping.smartbugs_swc("time_manipulation") is None
    assert mapping.smartbugs_swc("front_running") is None
    assert mapping.solidifi_swc("TOD") is None
    assert mapping.solidifi_swc("Timestamp-Dependency") is None


def test_accessors_round_trip_the_maps() -> None:
    assert mapping.smartbugs_swc("reentrancy") == "SC08"
    assert mapping.solidifi_swc("Overflow-Underflow") == "SC09"
    assert mapping.slither_swc("controlled-delegatecall") == "SC10"
    assert mapping.mythril_swc("SWC-107") == "SC08"


def test_unprotected_ether_send_is_not_mapped() -> None:
    """SWC-105 / arbitrary-send-eth are deliberately out: not in the method's Priv set."""
    assert mapping.slither_swc("arbitrary-send-eth") is None
    assert mapping.mythril_swc("SWC-105") is None


def test_slither_has_no_sc09_detector() -> None:
    """Slither ships no overflow detector, so its SC09 recall is zero by construction."""
    assert "SC09" not in set(mapping.SLITHER_CLASS.values())
