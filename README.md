# LA-IoT

LA-IoT connects sensitivity-aware report protection with authenticated Bayesian
fusion. Sensitive reports use joint reversible framing, ML-KEM-768, HKDF and
AES-256-GCM. Other reports carry BFV-encrypted integer statistics. The controller
verifies every original contribution and rebuilds the accepted result; the
recipient checks the authenticated result before obtaining the estimate.

## Install and use

Python 3.11 or later is required. Install the maintained package explicitly:

```sh
pip install -e '.[analysis,serial]'
laiot --help
```

The declared dependency ranges are in `pyproject.toml`. Save `pip freeze` and
backend/build versions with each executed experiment. No installation or Python
execution was performed while preparing this supplement.

Start with [the host deployment guide](docs/deployment.md). It provides a
four-source configuration, separate source/relay/controller/recipient commands,
role-specific key files, persistent retries and authenticated result receipts.
The generic Pico input adapter reads a bounded JSON line from a trusted local
UART or standard input. Optional calibration converts raw values to common units.
RPL, 6LoWPAN and IEEE 802.15.4 forwarding are supplied by the actual configured
network and border router.

## Maintained code

| Path | Purpose |
| --- | --- |
| `src/laiot/` | Canonical protocol, calibration, host services and accounting |
| `examples/` | Explicit synthetic input/configuration fixtures, not measured results |
| `Ablation Analysis/` | Five matched ablations, physical-unit RMSE and Gaussian NLL |
| `large_scale_evaluation/` | Component profiling, log adapters and network analysis |
| `tests/` | Unit and opt-in crypto integration test source |
| `docs/` | Deployment, logging, baseline interfaces and implementation status |

The modern chapter entry points redirect to `laiot` to avoid divergent protocol
copies. Older custom Ring-LWE chapter examples remain historical material.
The packaged wire format is version 5 and binds the complete configuration,
including calibration hash and encoding scales. Existing v3/v4 reports must not
be mixed into a v5 round.

## Fusion and evaluation

Independent measurements of a common quantity use calibrated inverse-variance
weights. Both protection paths converge to the same integer statistics, with
each scheduled source and the prior included once. The recipient restores the
configured physical scales after exact encoded arithmetic. BFV range checks
cover readings, weights and the complete roster before processing starts.

Use [the calibration and ablation fixtures](examples/README.md) for explicit
manual profiling. The ablations are LA-IoT, equal weights, no prior, relay off,
and uniform post-quantum protection. No source data or performance ranking is
generated automatically. Missing measurements remain missing.

[Experiment logging](docs/experiment_logging.md) distinguishes original-report
forwarding, provisional partial traffic, controller work and one identified
bottleneck link. Application bytes are not substituted for radio frames. Keep
actual per-hop traces and common-clock mappings with the run manifest.
[Baseline adapters](docs/baselines.md) accept actual reference implementations
with matched inputs and metric boundaries; they do not fabricate FGAMD, PATM or
FL-IoV implementations or results.

## Verification

Tests are supplied for explicit later execution:

```sh
python -m unittest discover -s tests -p 'test_*.py' -v
LAIOT_RUN_CRYPTO=1 python -m unittest discover -s tests -p 'test_*.py' -v
```

The second command explicitly enables ML-KEM/BFV key generation and integration
tests. No tests were run during source delivery. The GitHub workflow is
`workflow_dispatch` only; a push or pull request does not run Python.
See [implementation and evidence status](docs/implementation-status.md) for the
separation between host code, hardware integration and recorded experiments.

## License and citation

The project is licensed under [Apache-2.0](LICENSE); attribution is in [NOTICE](NOTICE).
Dependencies retain their own licenses. GitHub's citation metadata is provided
in [CITATION.cff](CITATION.cff).
