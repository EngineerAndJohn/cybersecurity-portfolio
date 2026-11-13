"""Response matching: only relevant replies classify; everything else is ignored."""

from __future__ import annotations

import unittest

from scapy.all import Ether, ICMP, IP, TCP  # type: ignore

from wqe7002_recon.matcher import (
    ICMP_KIND,
    RST_KIND,
    SYN_ACK_KIND,
    match_own_probe,
    match_reply,
)

from tests.support import (
    OUR_IP,
    OUR_MAC,
    TARGET_IP,
    TARGET_MAC,
    icmp_port_unreachable,
    probe_for,
    registry_for,
    rst_reply,
    syn_ack,
    syn_ack_wrong_ack,
    unrelated_frame,
)


class SynAckTests(unittest.TestCase):
    def test_syn_ack_with_correct_ack_matches_and_opens(self) -> None:
        probe = probe_for(80)
        match = match_reply(syn_ack(probe), registry_for(),
                            TARGET_IP, OUR_IP, OUR_MAC)
        self.assertIsNotNone(match)
        self.assertEqual(match.kind, SYN_ACK_KIND)
        self.assertEqual(match.probe.port, 80)
        self.assertEqual(match.probe.attempt, 1)
        self.assertEqual(match.syn_ack_ack, int(probe[TCP].seq) + 1)

    def test_syn_ack_with_wrong_ack_is_unrelated(self) -> None:
        probe = probe_for(80)
        self.assertIsNone(
            match_reply(syn_ack_wrong_ack(probe), registry_for(),
                        TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_second_attempt_probe_matches_its_own_record(self) -> None:
        probe = probe_for(443, attempt=2)
        match = match_reply(syn_ack(probe), registry_for(),
                            TARGET_IP, OUR_IP, OUR_MAC)
        self.assertIsNotNone(match)
        self.assertEqual(match.probe.attempt, 2)


class RstTests(unittest.TestCase):
    def test_rst_classifies_closed(self) -> None:
        probe = probe_for(443)
        match = match_reply(rst_reply(probe), registry_for(),
                            TARGET_IP, OUR_IP, OUR_MAC)
        self.assertIsNotNone(match)
        self.assertEqual(match.kind, RST_KIND)
        self.assertEqual(match.probe.port, 443)

    def test_rst_with_zero_ack_goes_to_the_latest_attempt(self) -> None:
        probe = probe_for(22, attempt=2)
        reply = rst_reply(probe)
        reply[TCP].ack = 0
        match = match_reply(reply, registry_for(),
                            TARGET_IP, OUR_IP, OUR_MAC)
        self.assertIsNotNone(match)
        self.assertEqual(match.kind, RST_KIND)
        self.assertEqual(match.probe.attempt, 2)


class IcmpTests(unittest.TestCase):
    def test_relevant_icmp_unreachable_is_retained_with_code(self) -> None:
        probe = probe_for(8080)
        match = match_reply(icmp_port_unreachable(probe, code=3),
                            registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        self.assertIsNotNone(match)
        self.assertEqual(match.kind, ICMP_KIND)
        self.assertEqual(match.icmp_code, 3)
        self.assertEqual(match.probe.port, 8080)

    def test_unreachable_quoting_someone_elses_packet_is_ignored(self) -> None:
        probe = probe_for(8080)
        reply = icmp_port_unreachable(probe, code=3)
        reply[ICMP].payload[IP].dst = "10.9.9.9"
        self.assertIsNone(
            match_reply(reply, registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_gateway_sourced_unreachable_with_valid_quote_is_retained(
        self,
    ) -> None:
        # Unreachables normally come from a router, not the target; the
        # quoted original segment is what proves relevance.
        probe = probe_for(80)
        match = match_reply(
            icmp_port_unreachable(probe, code=13, source_ip="172.28.70.1"),
            registry_for(),
            TARGET_IP,
            OUR_IP,
            OUR_MAC,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.kind, ICMP_KIND)
        self.assertEqual(match.icmp_code, 13)
        self.assertEqual(match.probe.port, 80)

    def test_gateway_sourced_unreachable_with_bad_quote_is_ignored(self) -> None:
        probe = probe_for(80)
        reply = icmp_port_unreachable(probe, code=13, source_ip="172.28.70.1")
        reply[ICMP].payload[TCP].seq = 0xDEADBEEF
        self.assertIsNone(
            match_reply(reply, registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_irrelevant_icmp_type_is_ignored(self) -> None:
        probe = probe_for(80)
        reply = icmp_port_unreachable(probe, code=3)
        reply[ICMP].type = 8  # echo request, not an unreachable
        self.assertIsNone(
            match_reply(reply, registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_unreachable_with_unverifiable_quote_is_ignored(self) -> None:
        frame = (
            Ether(dst=OUR_MAC, src=TARGET_MAC)
            / IP(src=TARGET_IP, dst=OUR_IP)
            / ICMP(type=3, code=1)
        )
        self.assertIsNone(
            match_reply(frame, registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )


class UnrelatedTrafficTests(unittest.TestCase):
    def test_tcp_from_a_port_never_probed_is_ignored(self) -> None:
        self.assertIsNone(
            match_reply(unrelated_frame(), registry_for(),
                        TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_packet_from_another_source_is_ignored(self) -> None:
        probe = probe_for(80)
        reply = syn_ack(probe)
        reply[IP].src = "172.28.70.3"
        self.assertIsNone(
            match_reply(reply, registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_outbound_packet_is_ignored(self) -> None:
        probe = probe_for(80)
        self.assertIsNone(
            match_reply(probe, registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_non_ethernet_packet_is_ignored(self) -> None:
        probe = probe_for(80)
        self.assertIsNone(
            match_reply(probe[IP], registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_fin_ack_is_not_a_scan_response(self) -> None:
        probe = probe_for(80)
        reply = syn_ack(probe)
        reply[TCP].flags = "FA"
        self.assertIsNone(
            match_reply(reply, registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )


class OwnProbeTests(unittest.TestCase):
    def test_own_outbound_syn_is_identified(self) -> None:
        probe = probe_for(80)
        record = match_own_probe(probe, registry_for(),
                                 TARGET_IP, OUR_IP, OUR_MAC)
        self.assertIsNotNone(record)
        self.assertEqual(record.port, 80)
        self.assertEqual(record.attempt, 1)

    def test_own_second_attempt_syn_is_identified(self) -> None:
        probe = probe_for(443, attempt=2)
        record = match_own_probe(probe, registry_for(),
                                 TARGET_IP, OUR_IP, OUR_MAC)
        self.assertIsNotNone(record)
        self.assertEqual(record.attempt, 2)

    def test_own_closing_rst_is_not_a_probe(self) -> None:
        probe = probe_for(80)
        rst = probe.copy()
        rst[TCP].flags = "R"
        self.assertIsNone(
            match_own_probe(rst, registry_for(), TARGET_IP, OUR_IP, OUR_MAC)
        )

    def test_inbound_syn_ack_is_not_an_own_probe(self) -> None:
        probe = probe_for(80)
        self.assertIsNone(
            match_own_probe(syn_ack(probe), registry_for(),
                            TARGET_IP, OUR_IP, OUR_MAC)
        )


if __name__ == "__main__":
    unittest.main()
