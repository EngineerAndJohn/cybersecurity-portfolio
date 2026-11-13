"""Shared fixtures for the test suite.

Nothing in this module transmits or opens a socket: every test uses the fake
transport and the fake clock, and all packets are built in memory.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from scapy.all import Ether, ICMP, IP, TCP  # type: ignore

from wqe7002_recon.probes import sequence_for, source_port_for
from wqe7002_recon.scope import Scope
from wqe7002_recon.transport import FakeClock, FakeTransport

OUR_IP = "172.28.70.2"
TARGET_IP = "172.28.70.10"
OUR_MAC = "02:42:ac:1c:46:02"
TARGET_MAC = "02:42:ac:1c:46:0a"

# Byte-exact copy of the lecturer-issued scope
# <lab>/scopes/assignment-01-tcp-syn-scan.json, used read-only.
STANDARD_SCOPE_JSON = """{
  "capture_point": "workbench eth0; records the authorised scanner vantage point",
  "environment": "isolated-course-lab",
  "interface": "eth0",
  "maximum_attempts": 2,
  "maximum_rate_pps": 20,
  "option": "tcp-syn-scan",
  "ports": [
    22,
    80,
    443,
    8080
  ],
  "schema": "wqe7002-recon-scope-v1",
  "scope_id": "wqe7002-a1-standard-tcp-syn-scan-v1",
  "target": "172.28.70.10",
  "timeout_seconds": 1.5,
  "topology": "wqe7002-course-lab Compose internal bridge"
}
"""


def write_scope_file(text: str) -> str:
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".json", delete=False
    )
    handle.write(text)
    handle.close()
    return handle.name


def standard_scope() -> Scope:
    from wqe7002_recon.scope import load_scope

    return load_scope(write_scope_file(STANDARD_SCOPE_JSON))


def standard_scope_path() -> str:
    return write_scope_file(STANDARD_SCOPE_JSON)


def make_env():
    """Return (scope, clock, transport) wired for engine tests."""
    clock = FakeClock()
    transport = FakeTransport(our_ip=OUR_IP, our_mac=OUR_MAC,
                              target_mac=TARGET_MAC, clock=clock)
    return standard_scope(), clock, transport


def is_syn(packet) -> bool:
    return packet.haslayer(TCP) and int(packet[TCP].flags) & 0x02


def syn_ack(probe, seq: int = 0x0BADBEEF):
    """A SYN/ACK answering ``probe`` with a correct acknowledgement."""
    return (
        Ether(dst=OUR_MAC, src=TARGET_MAC)
        / IP(src=TARGET_IP, dst=OUR_IP)
        / TCP(
            sport=probe[TCP].dport,
            dport=probe[TCP].sport,
            flags="SA",
            seq=seq,
            ack=int(probe[TCP].seq) + 1,
        )
    )


def syn_ack_wrong_ack(probe):
    packet = syn_ack(probe)
    packet[TCP].ack = int(probe[TCP].seq) + 999
    return packet


def rst_reply(probe):
    """An RST (+ACK) answering ``probe``, as a closed port sends."""
    return (
        Ether(dst=OUR_MAC, src=TARGET_MAC)
        / IP(src=TARGET_IP, dst=OUR_IP)
        / TCP(
            sport=probe[TCP].dport,
            dport=probe[TCP].sport,
            flags="RA",
            seq=0,
            ack=int(probe[TCP].seq) + 1,
        )
    )


def icmp_port_unreachable(probe, code: int = 3, source_ip: str = TARGET_IP):
    """ICMP type 3 quoting the probe's IP/TCP, as a host or gateway sends."""
    return (
        Ether(dst=OUR_MAC, src=TARGET_MAC)
        / IP(src=source_ip, dst=OUR_IP)
        / ICMP(type=3, code=code)
        / IP(src=OUR_IP, dst=TARGET_IP)
        / TCP(
            sport=probe[TCP].sport,
            dport=probe[TCP].dport,
            flags="S",
            seq=int(probe[TCP].seq),
        )
    )


def unrelated_frame():
    """TCP from the target that answers no probe at all."""
    return (
        Ether(dst=OUR_MAC, src=TARGET_MAC)
        / IP(src=TARGET_IP, dst=OUR_IP)
        / TCP(sport=53, dport=53535, flags="SA", seq=1, ack=2)
    )


def probe_for(port: int, attempt: int = 1):
    """A SYN probe exactly as the engine builds it (for matcher tests)."""
    index = [22, 80, 443, 8080].index(port)
    return (
        Ether(dst=TARGET_MAC, src=OUR_MAC)
        / IP(src=OUR_IP, dst=TARGET_IP)
        / TCP(
            sport=source_port_for(index),
            dport=port,
            seq=sequence_for(index) + (attempt - 1) * 4096,
            flags="S",
        )
    )


def registry_for(ports=(22, 80, 443, 8080), attempts=2):
    from wqe7002_recon.matcher import ProbeRecord

    registry = {}
    for index, port in enumerate(ports):
        sport = source_port_for(index)
        registry[sport] = {
            attempt: ProbeRecord(
                port=port,
                source_port=sport,
                sequence=sequence_for(index) + (attempt - 1) * 4096,
                attempt=attempt,
            )
            for attempt in range(1, attempts + 1)
        }
    return registry


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
