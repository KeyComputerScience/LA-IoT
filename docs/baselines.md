# Matched baseline adapters

The repository does not replace FGAMD, PATM or FL-IoV with invented algorithms.
Supply an adapter for the actual reference implementation and retain its source
URL, commit, dependencies and security configuration. KEM microbenchmarks remain
separate from aggregation-protocol comparisons.

`python -m laiot.baselines PLAN.json --output results/paired-001` is an explicit
manual command. It has not been run during source delivery. The runner supplies
the same input and topology hashes, scenario and seed to each adapter, shuffles
execution order reproducibly, and checks the returned pairing and metric scopes.
Its own process wall time is not interpreted as report latency.

A plan has `workload`, `topology`, `scenario`, `seeds` and `implementations`.
Each implementation needs `method`, `revision`, `repository`, `command` (an
argument list) and positive integer `timeout_s`. The exact arguments `{request}`
and `{result}` are replaced by private run-local JSON paths. Commands are trusted
operator configuration, run without a shell, and must not contain secret values.

The request contains input paths, the common scenario and a `pairing` object.
The adapter writes a result with exactly `pairing`, `scope`, `metrics`, `counts`
and `evidence`. `pairing` must exactly match the request. Declare a description
for every metric's measurement boundary in `scope`. `evidence` is
`device_measurement`, `network_simulation` or `local_fusion_profile`.

The five metric fields are `rmse`, `nll`,
`wire_bytes_per_scheduled_round`, `latency_ms_per_completed_round`, and
`energy_mj_per_scheduled_round`. Missing observations use JSON null. Counts are
`scheduled_rounds`, `completed_rounds`, and `estimates`. No completed rounds means
no completed-round latency; no estimates means no accuracy score. NLL may be
negative. Source-copy forwarding and security functions belong in the scenario
and cost boundary for each implementation.

Only values from adapters with matching boundaries belong in a comparison.
Failure and timeout records stay in the output. This runner validates experiment
metadata and data format; it does not prove an external implementation correct.
