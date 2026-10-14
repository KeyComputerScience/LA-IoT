# Configuration fixtures

`calibration.json` and `workloads.json` are synthetic input fixtures, not
measurements or performance results. No experiment runs when these files are
opened. Calibrated values use integers or exact decimal/fraction strings.

`calibration.json` converts source readings with `gain * reading + offset`.
Its `variance` is in the source unit squared; the common-unit variance is
`gain**2 * variance`. With reading scale `S` and precision scale `P`, encode
readings as `round(S * x)` and weights as `round(P / variance)`. The prior uses
the same two scales. Retain the artifact SHA-256 in the authenticated
`ProtocolConfig.calibration_sha256`, along with `unit`, `reading_scale`, and
`precision_scale`. Scaling preserves relative weights up to documented rounding;
it does not make an arbitrary noninteger calibration exact.

The receiver restores mean `(U/W)/S` and variance `P/W`. BFV arithmetic is exact
for the encoded integers. Physical-unit conversion and rounding are separate
from encryption correctness. Choose a batching-compatible plaintext modulus
that covers the complete encoded workload before starting a run.

`workloads.json` contains four already encoded channels per source. Its truth
values are in that same encoded reading unit, not raw Fahrenheit/Celsius values.
The example's equal-weight precision is 10, preserving the sum of the source
weights 16 + 4. A different workload must declare its uniform precision, prior,
calibration provenance, and scales. The full/relay-off/uniform-PQC variants
retain the same inputs and statistical weights. Uniform-PQC changes every
source's processing policy to sensitive; the original sensitive fraction stays
in paired comparison records, and the applied fraction is recorded separately.

After installing the package, the following are optional manual commands; they
have not been executed during code delivery:

```sh
python 'Ablation Analysis/aggregation_ablation.py' examples/workloads.json --output results/ablation-001 --environment-note 'record actual board, CPU policy, role placement, and software build'
python 'Ablation Analysis/plot_aggregation_ablation.py' results/ablation-001/runs.jsonl --output results/ablation-001-analysis
```

The runner records local processing, exact recovery, physical-unit RMSE, and
Gaussian posterior NLL against the known latent reference. NLL may be negative.
For predictions of future noisy readings, add the new measurement variance
before evaluating NLL. No radio traffic, board energy, or wireless latency is
inferred from the local profile; absent measurements remain absent.
