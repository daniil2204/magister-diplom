"""The parameter sets of the evaluation runs (chapter 2.3).

Every configuration is a `hsa.config.Config`, so the coefficients live in one place and nothing here
re-implements the method. Two kinds of set are produced:

* the four configurations M1-M4 (`modes`), which differ only in the Mode flag -- M2 drops the
  symbolic stage, M3 drops N*_t pruning, M4 shuffles the queue. These are compared head to head;
* the sensitivity sweeps (`lambda_sweep`, `weight_sweep`, `k_sweep`), each varying ONE axis around
  the default and holding the rest at the method's defaults. They answer "how much does this one
  coefficient move the result", so a one-axis sweep -- not a full grid -- is what chapter 2.3 asks
  for. The default point (lambda = 0.5, weights 0.4/0.4/0.2, k = 2) lies inside every sweep, so the
  three sweeps meet at M1 and the curves are directly comparable.

How a sweep is run matters for cost and is fixed in chapter 2.3:

* lambda and the weights only change the queue order and the budget split B_t (2.17, 2.18), never a
  single-target verdict. So they are REPLAYED offline from one reference run (`run.py`), not
  re-executed. `replay_sweep` gathers exactly those configurations;
* k changes loop unrolling, hence the verdicts themselves, so it must be re-executed. `k_sweep` is
  run on the ~40-contract subsample, not the whole sample.
"""

from __future__ import annotations

from hsa.config import Config, Mode

#: The experiment-wide seed. Used for the M4 queue shuffle and the SolidiFI sample draw, so both are
#: reproducible from this one number (chapter 2.3, "a fixed seed").
SEED = 20261030

#: The default point of every sweep, i.e. the full method M1. Written out so the sweeps can be read
#: as "M1 with one coefficient changed".
BASE = Config(mode=Mode.M1, seed=SEED)

#: lambda values of the sensitivity analysis (2.17). 0 ignores the branch-count penalty, 1 doubles
#: its exponent; 0.5 is the method default.
LAMBDAS = (0.0, 0.5, 1.0)

#: (alpha, beta, gamma) weight triples (2.16). The default, then two that tilt toward A and toward
#: D, then the uniform split. Each sums to 1 so R stays in [0, S(v)].
WEIGHTS = (
    (0.4, 0.4, 0.2),
    (0.6, 0.2, 0.2),
    (0.2, 0.6, 0.2),
    (1 / 3, 1 / 3, 1 / 3),
)

#: Loop-unrolling counts k (2.19). The default is 2; 1 and 3 bracket it.
KS = (1, 2, 3)


def modes() -> dict[str, Config]:
    """The four head-to-head configurations M1-M4, each at the default coefficients."""
    return {mode.value: BASE.with_(mode=mode) for mode in Mode}


def lambda_sweep() -> dict[str, Config]:
    """M1 with lambda varied over LAMBDAS, the rest at the defaults."""
    return {f"lam{value:.1f}": BASE.with_(lam=value) for value in LAMBDAS}


def weight_sweep() -> dict[str, Config]:
    """M1 with (alpha, beta, gamma) varied over WEIGHTS, the rest at the defaults."""
    return {
        _weight_name(alpha, beta, gamma): BASE.with_(alpha=alpha, beta=beta, gamma=gamma)
        for alpha, beta, gamma in WEIGHTS
    }


def k_sweep() -> dict[str, Config]:
    """M1 with k_unroll varied over KS. Re-executed, not replayed: k changes the verdicts."""
    return {f"k{value}": BASE.with_(k_unroll=value) for value in KS}


def replay_sweep() -> dict[str, Config]:
    """The configurations REPLAYED from the reference run: only the lambda and weight sweeps.

    lambda and the weights change solely the queue order and the budget split B_t (2.17, 2.18), never
    a single-target verdict, so a sweep over them is re-derived from one reference run.

    The four head-to-head configurations M1-M4 are NOT replayed -- each is a real timed run with its
    own times:

    * M3 (no N*_t pruning) changes which branches the engine explores inside a target, so it changes
      the target's own verdict AND time. Replaying it from the pruned reference run would make M3 look
      faster than it is -- which is exactly the hypothesis (directed search is faster) it must prove,
      not assume.
    * M4's hypothesis compares M1 and M4 by MEASURED time, not modelled time.
    * M2 has no symbolic stage to replay.

    k is likewise excluded: it changes loop unrolling, hence the verdicts, and is re-executed on the
    subsample (`k_sweep`).
    """
    configs: dict[str, Config] = {}
    configs.update(lambda_sweep())
    configs.update(weight_sweep())
    return configs


def _weight_name(alpha: float, beta: float, gamma: float) -> str:
    return "w{:02d}-{:02d}-{:02d}".format(round(alpha * 100), round(beta * 100), round(gamma * 100))
