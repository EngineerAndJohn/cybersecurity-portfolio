"""Packet construction.

Every frame this tool transmits is built here from the validated scope
parameters; nothing is assembled from user-supplied free text.
"""

from __future__ import annotations

from scapy.all import ARP, Ether, IP, TCP  # type: ignore

# Source ports are derived deterministically from the port's position in the
# sorted manifest list, which makes response matching unambiguous without
# any randomness in the probe schedule.
SPORT_BASE = 40000


def source_port_for(index: int) -> int:
    """Deterministic ephemeral source port for probe position ``index``."""
    return SPORT_BASE + index


def sequence_for(index: int) -> int:
    """Deterministic initial sequence number for probe position ``index``.

    The value itself is arbitrary; what matters is that the scanner knows it
    exactly, so a SYN/ACK can be verified with ``ack == seq + 1`` rather than
    matched on addresses alone.
    """
    return 0x0E0001C0 + index * 0x1000


def build_arp_who_has(
    target_ip: str,
    source_ip: str,
    source_mac: str,
) -> "Ether":
    """ARP request used once per run to resolve the target's MAC address."""
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=source_mac)
        / ARP(op=1, hwsrc=source_mac, psrc=source_ip, pdst=target_ip)
    )


def build_syn_probe(
    target_ip: str,
    source_ip: str,
    source_mac: str,
    target_mac: str,
    source_port: int,
    sequence: int,
    destination_port: int,
) -> "Ether":
    """One SYN probe: Ethernet / IPv4 / TCP with the SYN flag set."""
    return (
        Ether(dst=target_mac, src=source_mac)
        / IP(src=source_ip, dst=target_ip)
        / TCP(
            sport=source_port,
            dport=destination_port,
            seq=sequence,
            flags="S",
            window=64240,
        )
    )


def build_closing_rst(
    target_ip: str,
    source_ip: str,
    source_mac: str,
    target_mac: str,
    source_port: int,
    destination_port: int,
    syn_ack_seq: int,
    syn_ack_ack: int,
) -> "Ether":
    """RST that closes a half-open exchange after a SYN/ACK was observed.

    RFC 793 semantics: the RST carries ``seq = ack`` of the SYN/ACK we are
    answering; no acknowledgement is owed for a pure reset.
    """
    return (
        Ether(dst=target_mac, src=source_mac)
        / IP(src=source_ip, dst=target_ip)
        / TCP(
            sport=source_port,
            dport=destination_port,
            seq=syn_ack_ack,
            ack=syn_ack_seq + 1 if syn_ack_seq else 0,
            flags="R",
            window=0,
        )
    )
