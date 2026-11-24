"""Tests for the evaluation parameter sets of `experiments.configs`.

These pin the shape of the sensitivity analysis: the four modes, the three one-axis sweeps, and the
rule that lambda / weight sweeps are replayable while k is not.
"""

from __future__ import annotations

from hsa.config import Mode
from experiments import configs


def test_modes_cover_m1_to_m4_at_the_defaults() -> None:
    modes = configs.modes()
    assert set(modes) == {"M1", "M2", "M3", "M4"}
    for name, config in modes.items():
        assert config.mode is Mode[name]
        assert config.lam == configs.BASE.lam
        assert (config.alpha, config.beta, config.gamma) == (
            configs.BASE.alpha,
            configs.BASE.beta,
            configs.BASE.gamma,
        )
        assert config.k_unroll == configs.BASE.k_unroll


def test_lambda_sweep_varies_only_lambda() -> None:
    sweep = configs.lambda_sweep()
    assert {c.lam for c in sweep.values()} == set(configs.LAMBDAS)
    for config in sweep.values():
        assert config.mode is Mode.M1
        assert (config.alpha, config.beta, config.gamma) == (0.4, 0.4, 0.2)


def test_weight_sweep_triples_sum_to_one() -> None:
    sweep = configs.weight_sweep()
    assert len(sweep) == len(configs.WEIGHTS)
    for config in sweep.values():
        assert abs(config.alpha + config.beta + config.gamma - 1.0) < 1e-9
        assert config.lam == 0.5


def test_k_sweep_varies_only_k() -> None:
    sweep = configs.k_sweep()
    assert {c.k_unroll for c in sweep.values()} == set(configs.KS)
    for config in sweep.values():
        assert config.mode is Mode.M1
        assert config.lam == 0.5


def test_the_default_point_lies_in_every_sweep() -> None:
    """The three sweeps meet at M1, so the curves are comparable."""
    assert any(c.lam == 0.5 for c in configs.lambda_sweep().values())
    assert any(
        (c.alpha, c.beta, c.gamma) == (0.4, 0.4, 0.2) for c in configs.weight_sweep().values()
    )
    assert any(c.k_unroll == 2 for c in configs.k_sweep().values())


def test_replay_sweep_is_only_the_lambda_and_weight_sweeps() -> None:
    """Only lambda and the weights are replayed: they change the queue order and B_t, never a
    single-target verdict. The four modes M1-M4 are real timed runs (M3's pruning and M4's measured
    comparison need genuine verdicts/times), k is re-executed, and M2 has no symbolic stage."""
    replay = configs.replay_sweep()
    assert not ({"M1", "M2", "M3", "M4"} & set(replay))
    assert not any(name.startswith("k") for name in replay)
    assert set(configs.lambda_sweep()) <= set(replay)
    assert set(configs.weight_sweep()) <= set(replay)
    assert set(replay) == set(configs.lambda_sweep()) | set(configs.weight_sweep())


def test_names_are_unique_and_filesystem_safe() -> None:
    names = [
        *configs.modes(),
        *configs.lambda_sweep(),
        *configs.weight_sweep(),
        *configs.k_sweep(),
    ]
    assert len(names) == len(set(names))
    for name in names:
        assert all(ch.isalnum() or ch in "-._" for ch in name), name


def test_m4_seed_is_the_fixed_experiment_seed() -> None:
    assert configs.modes()["M4"].seed == configs.SEED
