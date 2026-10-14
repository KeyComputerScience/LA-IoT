# Host services and IoT integration

This supplement connects source protection, application relay processing,
controller verification and recipient recovery through IPv6/UDP CoAP services.
The new source has been statically reviewed only; the commands below are for
explicit later execution by the operator. No deployment, key generation,
benchmark or test was run while preparing these files.

## Roles and trust

| Role | Provisioned material | Processing |
| --- | --- | --- |
| Trusted Pico + Pi source terminal | Its own device master credential; public ML-KEM key and BFV context; source schedule | The Pico supplies four encoded readings. The Pi protects and persists the complete report, then transmits the saved bytes. Source and watermark MAC keys are derived for separate purposes from the device master. |
| Application relay | Public BFV context and public source schedule; no source, watermark, result or decryption keys | Persists and forwards every original unchanged. Separately builds one provisional BFV partial from non-sensitive reports. |
| Trusted controller | Source credentials; ML-KEM private seed; public BFV context; result credential; exact round schedule | Fully verifies each original, restores sensitive readings, rebuilds accepted encrypted statistics, and includes each source and prior once. |
| Authorized recipient | Private BFV context; result credential; independently provisioned `TrustedRound` | Authenticates and decrypts the final result, records exact fractions, and returns an authenticated receipt. |

The trusted configuration comes from the operator, not incoming packets.
Sensitive report confidentiality uses the existing ML-KEM/HKDF/AES-GCM
construction under its stated component assumptions. BFV supports encrypted
integer addition. The controller computes the accepted result from verified
originals, never from a relay's provisional ciphertext.

`config.py` writes owner-only role files and refuses to overwrite existing key
files. Run services under a dedicated local account. Move each role directory
and the required `public/` directory to its intended host over a trusted channel;
retain the generated relative paths, owner and permissions. Source hosts receive
only their own credential. Relays receive no secret-key files. Keep the recipient
BFV secret away from the controller. Preserve every role database across restarts.
Use separate state directories for different service processes.

## Explicit host-only example

`examples/service-config-plan.json` describes four logical sources, one relay,
one controller and one recipient on IPv6 loopback. This is a small host
integration configuration, not a wireless measurement or Pico firmware.
Its readings are already integers in common units and precisions are explicit
example weights. Use a recorded calibration profile for sensor measurements.

After manually installing the package and compatible dependencies, provision:

```sh
laiot provision --plan examples/service-config-plan.json --output private-demo
```

This is the only CLI operation that generates keys. It creates a public BFV
context, ML-KEM public key, controller-only 64-byte ML-KEM seed, recipient-only
BFV private context, independent source credentials and an independent result
credential. It also registers the exact round descriptor in the controller
database and gives its hash and roster to the recipient. If setup fails, inspect
the incomplete directory and use a new output directory rather than mixing keys.

In separate terminals, start the receiver, controller and relay:

```sh
laiot start-recipient --config private-demo/recipient/config.json
laiot start-controller --config private-demo/controller/config.json
laiot start-relay --config private-demo/relay-1/config.json
```

Then submit one report for each scheduled source:

```sh
laiot source --config private-demo/source-1/config.json --readings 10 12 11 13
laiot source --config private-demo/source-2/config.json --readings 11 13 12 14
laiot source --config private-demo/source-3/config.json --readings 9 11 10 12
laiot source --config private-demo/source-4/config.json --readings 10 12 11 13
```

The four slots are fused independently. The controller's durable deadline starts
on its first service launch and survives restart; the example allows 600 seconds.
No complete result is finalized until all four originals pass verification.
The controller then delivers the saved final result to the recipient.
`private-demo/recipient/posterior.json` contains encoded and restored physical
means and variance as numerator/denominator pairs, together with scales and unit.
The physical mean is the encoded mean divided by `reading_scale`; physical
variance is `precision_scale` times the inverse encoded total precision.

Services continue listening until interrupted, allowing exact-byte retries.
The source's JSON command output is only a transport acknowledgment from its
immediate endpoint. It is not an authenticated assertion of final fusion.
The controller records successful delivery only after checking the recipient's
HMAC receipt, bound to the exact result hash, round, context and schedule.

## Local Pico input

The generic adapter accepts one bounded line of already encoded readings:

```json
{"readings":[10,12,11,13]}
```

Identity, sensitivity, precision, round and sequence come from trusted source
configuration; input data cannot override them. Exactly four non-Boolean
integers within the configured reading range are accepted. Examples:

```sh
laiot source --config private-demo/source-1/config.json --input examples/sensor-input.json
laiot source --config private-demo/source-1/config.json --uart /dev/ttyACM0 --baudrate 115200
```

The UART command requires the optional serial dependency and operator-provided
Pico firmware that emits the agreed reading format. Protect the local interface
and map the actual physical device to its source configuration. This adapter is
not an RP2040 port, sensor driver or an IEEE 802.15.4 driver.

Alternatively, add `--calibration path/to/calibration.json` to interpret the four
input integers as raw sensor values. The source checks the artifact hash, common
unit, reading/precision scales, prior and its own encoded precision against its
provisioned configuration before applying the saved gain and offset. Encoded
readings must still fit the protocol bounds. Provision these exact calibration
fields and integer weights in the plan before generating a round; the example
plan uses direct encoded input. Neither a sensor input line nor a different
calibration artifact can silently change the scheduled weights or units.

## Transfer, relay work and retries

All report-ingress services use confirmable `POST /laiot/reports`, with bounded
Block1 assembly and a common configured block size. For a real deployment, put
the actual IPv6 addresses in the plan and provide the Contiki border router,
RPL paths, 6LoWPAN adaptation, radio driver and interface configuration separately.

The source saves ciphertext before transfer. Repeating its scheduled
`(node, round, sequence)` sends the frozen report, even if a new input line is
supplied. Use a new provisioned round and sequence for new measurements. Sequence
changes and new rounds require an updated trusted schedule for all relevant roles.

A relay has no source MAC keys, so its initial check is syntactic. It keeps at
most four bounded candidates per source and forwards them for controller
verification. Explicit upstream rejection removes that candidate, permitting a
different candidate for the same source. A transport acknowledgment marks the
original as forwarded; the final controller ledger remains authoritative.
The relay freezes at most one provisional batch when all assigned originals
are forwarded or its configured partial deadline is reached. It keeps forwarding
late original reports independently. Provisional failures never substitute for
original verification. A relay-only receipt establishes durable hop admission,
not end-to-end source authenticity.

The relay partial envelope has its own domain marker, round, context, original
hashes and bounded statistics bytes. Controller ingress checks this separate
format and records it only as provisional telemetry. Relay partials do not
change the accepted posterior, scheduled participant roster or prior count.
Original copies, partial traffic and complete controller reconstruction are all
retained in the cost accounting.

For the paired relay ablation, use a fresh matched run/state directory and add
`--disable-partials` to `start-relay`. This omits provisional BFV computation and
partial transmission while preserving every original and the controller's
accepted-result calculation. Keep the same source set, readings, transport,
route, hardware placement and deadline. Do not reuse an already completed
database as a new measurement run.

Recipient acceptance, the authenticated receipt and exact posterior are committed
in one database transaction. An identical result retry returns the cached receipt
without decrypting or releasing another posterior. A conflicting result is
rejected. If exporting the JSON file is interrupted, the accepted posterior is
still in SQLite and is exported again on restart. The authenticated receipt is
available at `GET /laiot/receipts`; it contains no posterior or secret.

## Logs and deployment evidence

Services emit metadata-only `LAIOT_EVENT` JSON records to stderr. Save them with
the run manifest. Source preparation, relay BFV work, controller verification,
recovery, re-encryption and reconstruction, recipient acceptance and confirmed
delivery have separate records. `REPORT_ACCEPT` counts fully verified sources;
`ROUND_COMPLETE` follows authenticated recipient confirmation. A verified subset
does not constitute a complete round.

Application records contain `report_bytes` and are not wireless frame counts.
Obtain actual per-hop headers, fragments, acknowledgments and retransmissions
from the radio/trace adapter. Measure original forwarding, relay partials,
controller reconstruction and one named bottleneck link separately. Per-link
load uses that link's own transmissions and observation window. Do not derive
single-link load from network-wide byte totals.

Each process receives a new monotonic clock domain. Controller release and
confirmed delivery can be compared within one uninterrupted domain. Recipient
acceptance on another host requires a recorded clock mapping; receipt arrival
is a separate confirmed-delivery metric. Preserve failed and timed-out rounds.
Round release, verified source admission, timeout, recipient acceptance and confirmed delivery are saved
through a metadata outbox in the same transaction as their state changes. After
restart, pending events retain their original timestamps and clock domains;
stable event IDs allow exact duplicate output to be removed. Their timestamps
identify the transaction's recording point rather than a separate post-commit
boundary. Save stderr durably; stream flushing alone does not certify external
log storage. Other profiling records are direct console events, so a crash can
leave an incomplete stage profile. Missing timing records remain missing rather
than receiving invented timestamps. For a new experimental run, choose a new
run identifier and state directory.

Archive actual firmware builds, platform/radio drivers, Contiki/Cooja commits,
topologies, frame traces, process placement, host versions and independently
measured power traces. The small loopback configuration demonstrates the intended
execution wiring once run; hardware feasibility, wireless performance and
5,000-node completion require their own recorded execution evidence.
