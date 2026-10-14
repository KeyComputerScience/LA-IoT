# Experiment code (not executed)

All Python files were generated and reviewed as text only. No Python process,
import, AST parser, compiler, benchmark, simulator, or test was invoked. Empty
CSV files are schemas, not measurements. No numerical result is supplied.

`pqc_benchmark.py` explicitly runs five requested parameter sets in isolated
workers. It queries enabled OQS names; an unavailable scheme stays unavailable.
There is no fallback to another parameter set. Pin the official liboqs build
to 0.16.0 and record its source revision, compiler, build options, and matching
official liboqs-python revision. `oqs_version()` and the binding version are
exported when available. A library-version mismatch is recorded as unavailable;
changing the required version requires an explicit CLI option. No key, shared secret, or unencrypted real reading is
logged. The same 96 synthetic bytes and logical packet metadata are used by
default. The KEM ciphertext is additionally bound as AEAD associated data.
Include public-key provisioning traffic separately; it is not in body bytes.

These are crypto component benchmarks on the executing Linux host. They do
not establish 32 KB sensor deployment, BFV performance, IND-CCA security, or
whole-protocol speed. Peak RSS includes the Python interpreter and libraries.
Timing confidence intervals across trials describe that worker session;
repeat benchmark sessions independently to study host-to-host/run variation.

`network_adapter.py` accepts actual log lines containing `LAIOT_EVENT ` followed
by one JSON object matching `events_template.csv`. A log line must name its
clock domain. Reboots need a new domain. Other diagnostic lines are counted
as ignored. The adapter records SHA-256 hashes and never simulates a network.
`inventory` records requested existing artifacts; populate Contiki/Cooja
revisions, actual target, firmware ELF, linker map, radio driver, peak RAM, and
clock-mapping evidence from real builds. `verify` checks recorded file hashes;
hash agreement alone is not evidence of execution or authorship.

`rounds_template.csv` includes every scheduled round. `status` is `complete`,
`timeout`, or `rejected`; a complete round requires the expected participant
set. `jct_ms` is measured from round release to confirmed authenticated result
delivery for complete rounds, or to the timeout/rejection decision for failed
rounds. `decision_s` is the confirmed delivery time for a successful round,
and the deadline/rejection time otherwise. In the new `laiot.end_to_end`
output, `latency_ms` is an alias of `e2e_latency_ms`: round release to recipient
acceptance, supplied only for complete rounds with a valid clock mapping.
Historical source-to-controller latency must be kept as a separately named
metric and must not be pooled with recipient-acceptance latency. Record
the same clock or an independently calibrated mapping. Give every experiment
condition a different `scenario_id`; include scale, sensitivity fraction,
topology, attack setting, traffic rate, and timeout in the run manifest.

`analyze_results.py` summarizes means and bootstrap 95% intervals across
independent network runs. A single run has no estimated interval. Completion
uses all scheduled rounds. Completed JCT and report latency are always
accompanied by completion. All-round decision time is exported separately.
Incomplete rounds are not silently assigned zero latency. Runs
without any complete round have no latency estimate. Different scenarios
are never pooled. The comparison CSV uses baseline-normalized reductions for
time/energy and percentage-point differences for completion; these are point
comparisons, not statistical significance tests. Result CSVs include sample counts and blank unavailable
intervals. Network figures have four panels (completed JCT, energy,
completion, and conditional latency); crypto figures show measured component
timing and body sizes. Both PNG and PDF use Times New Roman, white background,
black text, and red LA-IoT bars. Install that font before plotting; there is
no silent font substitution. Missing input creates no fabricated result plot.
`results_analysis_generated.tex` contains English paragraphs built from the
actual summary only; it is not generated when there are no observations.
The microbenchmark records body bytes and complete micro-envelope bytes
separately. The latter includes the domain, logical metadata, KEM ciphertext,
nonce, AEAD ciphertext/tag, and source MAC; neither includes CoAP/radio headers.

Measured power is sampled in watts against seconds and integrated by the
trapezoid rule, then multiplied by 1000 to obtain mJ. Every component must
cover the full common experiment window and represent a disjoint physical
scope. Model energy uses exclusive state durations in seconds times calibrated
power in mW. Declare each component's `scope_id` and its `exclusive_states` in
the energy profile; record zero durations explicitly. Never add board-total
power and that board's CPU/radio/memory energies. Model energy and measured
energy require separate analysis invocations and have separate figure names.
Total run energy is divided by all scheduled rounds, including unsuccessful
ones. Supply the calibration artifact path and its SHA-256 in the profile;
the analyzer verifies that hash. Supply the common `clock_domain` there too.
Round CSV records `release_s` and `decision_s`; JCT is checked against those
timestamps. Power traces must have samples exactly at the first round release
and last round decision after documented clock alignment. State durations
must cover that same full window. An energy analysis requires energy for every
declared run. Missing boundary samples or components cause an explicit error.

Example commands below are provided for later manual execution only:

```sh
python pqc_benchmark.py --output results/crypto_run01 --run-id crypto_run01
python network_adapter.py normalize --logs actual_serial.log --output actual_events.csv
python network_adapter.py inventory --root experiment_run01 --files firmware.elf firmware.map serial.log
python network_adapter.py verify --manifest experiment_run01/manifest.json --root experiment_run01
python analyze_results.py --rounds actual_rounds.csv --power actual_power.csv --energy-profile measured_profile.json --output results/network_measured
python analyze_results.py --rounds actual_rounds.csv --energest actual_states.csv --energy-profile modeled_profile.json --output results/network_modeled
python analyze_results.py --benchmark results/crypto_run01/benchmark_raw.csv --output results/crypto_figures
```

The `protocol/` files now redirect to the canonical installed `laiot` package.
Its version 5 report encoding authenticates the complete configuration hash,
including calibration and encoding scales, while retaining the ML-KEM/HKDF/
AES-GCM sensitive suite and BFV statistics. Chapter-history versions are not
mixed into a current round. The network adapter does not change the protocol.
Collect full-path costs separately: WC, source authentication, sensitive
KEM/AEAD, lossless outer framing, CoAP blocks, radio fragments, source-copy
forwarding, provisional aggregation, verification, BFV reencryption and
recomputation, and authenticated delivery. No Contiki port or 5,000-node run
is claimed by this source package.

`full_pipeline_profile.py` explicitly profiles the bundled reference modules
under `protocol/` on the executing host. It includes provisioning, source
protection, three logical relay groups, controller verification/restoration
and BFV reencryption, result authentication, and authorized decryption.
Independent integer arithmetic checks the accepted posterior. The reference
encodes four readings in 18 bytes, separately from the 96-byte KEM workload.
Its CSV is a host stage profile, not a network round CSV, and must not be
fed directly into network plots as if it contained radio measurements.
Only the ML-KEM suite is integrated in that full path. Alternative KEM
microbenchmarks do not establish complete-system variant performance.

