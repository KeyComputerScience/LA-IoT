# Implementation and evidence

The packaged entry point is `laiot`; its maintained code is in `src/laiot`.
The original chapter folders are retained for manuscript history. The modern
IoT and authenticated-fusion entry points redirect to the package. Older custom
Ring-LWE examples are historical examples, not the sensitive-data security suite.

The packaged wire format is version 5. It authenticates a configuration hash
covering units, reading/precision scales, calibration hash, prior and BFV bounds.
Version 3/4 report bytes are not silently reinterpreted as version 5.

The supplement was authored and statically inspected without running Python,
imports, AST parsing, bytecode compilation, tests, key generation, network
listeners, benchmarks or simulators. Test files are supplied for explicit later
execution. The CI workflow is manual-only and has no push or PR trigger.

The host services use the existing ML-KEM/HKDF/AES-GCM and BFV components.
The sensitive envelope has the conditional IND-CCA scope stated by the protocol;
BFV supports encrypted computation under its separate confidentiality model.
Application tests check implementation behavior rather than prove cryptography.

Real experiments must save the topology, hardware placement, calibration,
clock mapping, measured power or labeled energy model, seeds and raw logs.
No synthetic costs, assumed rankings, or detection rates are supplied as measured
results. The original forwarding, provisional partials, controller work and
selected-link load are distinct accounting scopes.

Board-specific Pico/802.15.4 firmware and a supported Contiki RP2040 port depend
on the selected hardware. The supplied host input adapter and Contiki evidence
resource do not establish such a deployment. Existing Cooja configurations and
baseline implementations must be supplied with their revisions before reporting
corresponding network or comparative measurements.

FGAMD, PATM and FL-IoV are comparison targets, not bundled reimplementations.
Use the documented baseline adapter with an actual reference implementation;
do not substitute KEM-only timings for complete aggregation protocol costs.

