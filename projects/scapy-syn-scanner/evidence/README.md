# Evidence — provenance and sanitisation notes

Each file below is copied unchanged from the measured course-lab experiment
(10 Nov 2026), except `test-run.txt`, which is a fresh re-run of the test suite
against the repository copy of the source.

| File | Origin | Notes |
|---|---|---|
| `result.json` | Measured run inside the lab `workbench` container | Result document written by the tool; deterministic schema `wqe7002-recon-result-v1` |
| `trials.json` | Same container, `--execute --trials 5` | 5 repeated bounded trials with stability/RTT summary |
| `nmap-validation.xml` | Same container, Nmap 7.94SVN | The independent validation scan required by the brief |
| `scope.json` | Copied from the lecturer-issued scope manifest | The exact allow-list the tool executed |
| `dry-run-plan.txt` | Plan mode in the container | Validates scope and prints the probe schedule; transmits nothing |
| `experiment.pcap` | Course capture helper (tcpdump of the scanner's own exchange) | Contains only lab-private RFC1918 addresses |
| `SHA256SUMS` | Computed in the container after the capture stopped | Hashes of the five files above |
| `test-run.txt` | Re-run on a Windows host with Scapy 2.7.0, Python 3.12 | 77 tests, 77 pass, 0 packets transmitted — proves the repository copy is intact |

## Sanitisation

- All IP addresses are lab-private (172.28.0.0/16) and have no meaning outside
  the course lab.
- No credentials, tokens or personal data appear in any file.
- The PCAP contains only the scanner's own bounded exchange with the authorised
  lab target.
