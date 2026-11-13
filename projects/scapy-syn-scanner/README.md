# Bounded Scapy TCP SYN Scanner — Independently Validated with Nmap

**Coursework:** WQE7002 Assignment 1, Option B (TCP port scanner), Universiti Malaya.
**Run date:** 10 November 2026. **Live page:** [site version](./index.html).

A small network reconnaissance tool built with Scapy for the authorised course
lab. It constructs its own Ethernet/IPv4/TCP SYN probes, matches every reply to
the exact probe it answers, classifies each port, closes every SYN/ACK exchange
with an RST, and writes a deterministic JSON result document. The tool itself
never calls Nmap; Nmap appears once, as the independent validation scanner the
brief asks for.

## Objective

Build a TCP SYN scanner that (1) crafts raw probes instead of relying on
Nmap's engine, (2) classifies port states strictly from verifiable replies,
(3) cannot transmit outside a lecturer-issued scope, and (4) can be checked
against an independent Nmap run on the same target.

## Environment and tools

| Item | Value |
|---|---|
| Host | Dockerised course lab — `workbench` container, Linux, `eth0` |
| Scanner address | 172.28.70.2 |
| Authorised target | 172.28.70.10 (services host, from the scope manifest) |
| Ports | 22, 80, 443, 8080 (manifest allow-list, unchanged) |
| Language / libraries | Python 3.12.3, Scapy 2.7.0 |
| Validation tool | Nmap 7.94SVN (`-sS -n -Pn --max-rate 20 --max-retries 2`) |
| Capture | Course capture helper (tcpdump of the scanner's own exchange) |
| Bounds | at most 20 pps, 1.5 s per attempt, at most 2 attempts per port |

## Method, step by step

1. **Scope manifest.** Targets, ports and bounds come only from the lecturer-
   issued scope file; no CLI argument can name a target or port. Malformed,
   placeholder or out-of-bounds values are rejected before any probe is built.
2. **Deterministic probes.** One SYN probe per port: Ethernet + IPv4 + TCP/SYN,
   source ports 40000 + port index, fixed ISNs per port and attempt — so every
   reply can be tied to the exact probe it answers.
3. **ARP resolution.** The target MAC is resolved with an ARP exchange before
   each trial.
4. **Strict matching.** A reply counts only if it arrives on the scanning
   interface, is addressed to the scanner's own IP and matches a recorded probe:
   SYN/ACK must carry `ack = ISN + 1`; RST must come from the target; an ICMP
   type-3 unreachable is kept only when its quoted segment matches. Everything
   else (other hosts, own outbound frames, wrong acknowledgements) is ignored.
5. **Classification.** First definitive reply per port decides the state:
   SYN/ACK → `open`, RST → `closed`, ICMP → `filtered-icmp-unreachable`,
   silence after both attempts → `filtered-or-no-response`. A port resolved in
   attempt 1 is never probed again.
6. **Closing discipline.** Every SYN/ACK exchange is closed with an RST
   (`seq = ack` of that SYN/ACK). One pacing gate applies to everything the
   tool sends, keeping the run inside the manifest's 20 pps.
7. **Plan mode.** Without `--execute` the tool validates the scope and prints
   the full probe schedule without transmitting anything — this is the default
   behaviour.
8. **Trials extension.** `--trials N` repeats the same bounded scan N times and
   adds per-port outcome stability, RTT statistics, retry probes and
   second-attempt recoveries to the summary.
9. **Independent validation.** The same port set was scanned with Nmap on the
   same host, and the two result documents were compared observation by
   observation.
10. **Evidence hashing.** Every evidence file was copied from the container and
    SHA-256-hashed (`SHA256SUMS`).

## Results

- **All four in-scope ports open on the first attempt** (22/tcp, 80/tcp,
  443/tcp, 8080/tcp), with per-port RTTs of 0.124–0.395 ms — one LAN hop.
- **Complete agreement with Nmap** on every observation: port states, reason
  (`syn-ack`, ttl 64), target MAC `02:42:ac:1c:46:0a` and the sub-millisecond
  RTT class.
- **5 repeated trials:** 100 % outcome agreement, mean RTT 0.082–0.090 ms, zero
  retry probes (every first attempt answered immediately on this LAN).
- **77/77 offline unit tests pass** — construction, matching (unrelated,
  duplicate, missing, invalid), scope rejection, rate limiting, attempt bounds,
  determinism, CLI contract, retry/timing extension. Tests never transmit.
- **One diagnosed artifact:** the capture contains roughly twice as many RSTs as
  the tool sent. The Linux kernel on the scanner host also answers the SYN/ACKs
  it never requested with its own RSTs — a raw-socket artifact, confirmed by the
  same pattern in Nmap's run. Disclosed rather than hidden.

| Observation | Scapy tool | Nmap XML | Agreement |
|---|---|---|---|
| 22/tcp | open, 1 probe, rtt 0.395 ms | open, syn-ack, ttl 64 | agreement |
| 80/tcp | open, rtt 0.164 ms | open, syn-ack, ttl 64 | agreement |
| 443/tcp | open, rtt 0.124 ms | open, syn-ack, ttl 64 | agreement |
| 8080/tcp | open, rtt 0.192 ms | open, syn-ack, ttl 64 | agreement |
| Target MAC | 02:42:ac:1c:46:0a (ARP-resolved) | 02:42:ac:1c:46:0a | agreement |

## Repository layout

```
src/wqe7002_recon/   scope, probes, matcher, engine, transport, output, cli
tests/               77 offline unit tests (zero packets transmitted)
evidence/            the measured experiment (see below)
```

## Evidence

| File | What it is |
|---|---|
| [`evidence/result.json`](evidence/result.json) | The tool's measured result document (window, parameters, per-port states and observations) |
| [`evidence/trials.json`](evidence/trials.json) | 5 repeated bounded trials with stability and RTT summary |
| [`evidence/nmap-validation.xml`](evidence/nmap-validation.xml) | The independent Nmap run, XML output |
| [`evidence/scope.json`](evidence/scope.json) | The lecturer-issued scope manifest as executed |
| [`evidence/dry-run-plan.txt`](evidence/dry-run-plan.txt) | Plan mode output — validates the scope and prints the probe schedule without transmitting |
| [`evidence/experiment.pcap`](evidence/experiment.pcap) | Capture of the scanner's own exchange |
| [`evidence/SHA256SUMS`](evidence/SHA256SUMS) | SHA-256 hashes of every evidence file |
| [`evidence/test-run.txt`](evidence/test-run.txt) | Re-run of the 77-test suite on the repository copy (Windows host, Scapy 2.7.0) |
| [`evidence/README.md`](evidence/README.md) | Provenance notes for every file |

## What I would do differently

- **Adaptive per-port timeout.** Replace the fixed 1.5 s receive window with a
  timeout derived from the observed RTT distribution (median + 3σ, clamped to
  the manifest bound), so silent ports stop costing the full window. Guard
  tests against timeout oscillation across trials would come with it.
- **A classification-diversity run.** All four in-scope ports are open, so the
  closed, ICMP and no-response paths were only exercised in unit tests. A lab
  with closed and filtered ports in scope would exercise every classification
  path against real traffic.

## Safety

Targets and ports can only come from the scope manifest. Hard bounds (20 pps,
2 attempts, 30 ports) sit on top of whatever the manifest declares. There is no
stealth, spoofing or evasion code anywhere, and without `--execute` nothing
goes on the wire.
