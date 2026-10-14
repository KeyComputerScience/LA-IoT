# Changes

## 0.2.0 - source supplement

- Added the Apache-2.0 license, project notice and software citation metadata.
- Added one maintained `laiot` package and compatibility entry points.
- Added explicit source, relay, controller and recipient services, local sensor
  input, private role provisioning and authenticated delivery receipts.
- Bound units, encoding scales and calibration provenance to the version 5
  report configuration; added configurable BFV plaintext-range checks.
- Unified full report verification before persistent contribution admission.
- Added common-unit calibration, RMSE/NLL evaluation and uniform-PQC ablation.
- Added metadata events, transactional log outboxes and separate end-to-end,
  forwarding, controller and bottleneck-link accounting.
- Added external-baseline adapter validation without fabricated implementations.
- Added manual test sources and a manual-only GitHub verification workflow.

This supplement has been statically reviewed. Python, tests, key generation,
network services, firmware builds, benchmarks and simulations were not run.
No measured performance or security rates are supplied by the source supplement.
