"""Probe construction: exact wire fields, no placeholders, deterministic."""

from __future__ import annotations

import unittest

from scapy.all import ARP, Ether, IP, TCP  # type: ignore

from wqe7002_recon.probes import (
    build_arp_who_has,
    build_closing_rst,
    build_syn_probe,
    sequence_for,
    source_port_for,
)

from tests.support import OUR_IP, OUR_MAC, TARGET_IP, TARGET_MAC


class SynProbeTests(unittest.TestCase):
    def test_probe_has_exact_addressing_and_flags(self) -> None:
        probe = build_syn_probe(
            target_ip=TARGET_IP, source_ip=OUR_IP,
            source_mac=OUR_MAC, target_mac=TARGET_MAC,
            source_port=40001, sequence=0x0E0011C0, destination_port=80,
        )
        self.assertEqual(probe[Ether].dst, TARGET_MAC)
        self.assertEqual(probe[Ether].src, OUR_MAC)
        self.assertEqual(probe[IP].dst, TARGET_IP)
        self.assertEqual(probe[IP].src, OUR_IP)
        self.assertEqual(probe[TCP].dport, 80)
        self.assertEqual(probe[TCP].sport, 40001)
        self.assertEqual(int(probe[TCP].seq), 0x0E0011C0)
        self.assertEqual(int(probe[TCP].flags), 0x02)  # SYN and only SYN
        self.assertEqual(probe[TCP].ack, 0)

    def test_probe_survives_a_bytes_round_trip(self) -> None:
        probe = build_syn_probe(
            target_ip=TARGET_IP, source_ip=OUR_IP,
            source_mac=OUR_MAC, target_mac=TARGET_MAC,
            source_port=40003, sequence=sequence_for(3), destination_port=8080,
        )
        rebuilt = Ether(bytes(probe))
        self.assertEqual(rebuilt[Ether].dst, TARGET_MAC)
        self.assertEqual(rebuilt[IP].dst, TARGET_IP)
        self.assertEqual(rebuilt[TCP].dport, 8080)
        self.assertEqual(rebuilt[TCP].sport, 40003)
        self.assertEqual(int(rebuilt[TCP].flags), 0x02)

    def test_source_ports_and_sequences_are_deterministic(self) -> None:
        self.assertEqual(source_port_for(0), 40000)
        self.assertEqual(source_port_for(3), 40003)
        self.assertNotEqual(sequence_for(0), sequence_for(1))
        self.assertEqual(sequence_for(1), sequence_for(0) + 0x1000)


class ClosingRstTests(unittest.TestCase):
    def test_closing_rst_carries_the_syn_ack_acknowledgement(self) -> None:
        rst = build_closing_rst(
            target_ip=TARGET_IP, source_ip=OUR_IP,
            source_mac=OUR_MAC, target_mac=TARGET_MAC,
            source_port=40000, destination_port=22,
            syn_ack_seq=0x0BADBEEF, syn_ack_ack=0x0E0011C1,
        )
        self.assertEqual(int(rst[TCP].flags), 0x04)  # RST only
        self.assertEqual(int(rst[TCP].seq), 0x0E0011C1)
        self.assertEqual(rst[TCP].dport, 22)
        self.assertEqual(rst[TCP].sport, 40000)
        self.assertEqual(int(rst[TCP].window), 0)

    def test_closing_rst_never_carries_a_syn(self) -> None:
        rst = build_closing_rst(
            target_ip=TARGET_IP, source_ip=OUR_IP,
            source_mac=OUR_MAC, target_mac=TARGET_MAC,
            source_port=40002, destination_port=443,
            syn_ack_seq=1, syn_ack_ack=2,
        )
        self.assertEqual(int(rst[TCP].flags) & 0x02, 0)


class ArpRequestTests(unittest.TestCase):
    def test_arp_who_has_is_a_broadcast_request(self) -> None:
        request = build_arp_who_has(
            target_ip=TARGET_IP, source_ip=OUR_IP, source_mac=OUR_MAC,
        )
        self.assertEqual(request[Ether].dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(int(request[ARP].op), 1)
        self.assertEqual(request[ARP].pdst, TARGET_IP)
        self.assertEqual(request[ARP].psrc, OUR_IP)


if __name__ == "__main__":
    unittest.main()
