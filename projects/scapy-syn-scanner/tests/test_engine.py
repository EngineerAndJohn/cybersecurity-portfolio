"""Engine behaviour: plan mode, attempts, pacing, duplicates, closing RSTs."""

from __future__ import annotations

import unittest

from scapy.all import TCP  # type: ignore

from wqe7002_recon.engine import (
    CLOSED,
    NO_RESPONSE,
    OPEN,
    ScanEngine,
    build_plan,
)
from wqe7002_recon.probes import sequence_for

from tests.support import (
    make_env,
    is_syn,
    rst_reply,
    syn_ack,
)


def run_trial(clock, transport, scope):
    engine = ScanEngine(scope, transport, clock=clock, sleeper=clock.advance)
    return engine.run_trial()


class PlanTests(unittest.TestCase):
    def test_plan_mode_never_creates_a_transport_or_sends(self) -> None:
        scope, clock, transport = make_env()
        plan = build_plan(scope)
        self.assertEqual(len(plan.schedule), 8)  # 4 ports x 2 attempts
        self.assertFalse(transport.started)
        self.assertEqual(transport.sent, [])

    def test_plan_schedule_is_deterministic(self) -> None:
        scope, _, _ = make_env()
        first = build_plan(scope).schedule
        second = build_plan(scope).schedule
        self.assertEqual(first, second)
        self.assertEqual(first[0], (22, 1, 40000, sequence_for(0)))
        self.assertEqual(first[1], (22, 2, 40000, sequence_for(0) + 4096))
        self.assertEqual(first[4], (443, 1, 40002, sequence_for(2)))


class ClassificationTests(unittest.TestCase):
    def test_open_port_classifies_and_closes_with_rst(self) -> None:
        scope, clock, transport = make_env()
        transport.script(syn_ack, delay=0.01)
        result = run_trial(clock, transport, scope)
        port = next(p for p in result.ports if p.port == 22)
        self.assertEqual(port.state, OPEN)
        self.assertEqual(port.attempts_used, 1)
        kinds = [obs.kind for obs in port.observations]
        self.assertEqual(kinds, ["probe", "syn-ack"])
        # every open port gets exactly one closing RST from the tool
        self.assertEqual(result.closing_rsts_sent, 4)
        rsts = [pkt for pkt in transport.sent if int(pkt[TCP].flags) == 0x04]
        self.assertEqual(len(rsts), 4)
        self.assertTrue(all(int(pkt[TCP].flags) & 0x02 == 0 for pkt in rsts))

    def test_closed_port_classifies_via_rst(self) -> None:
        scope, clock, transport = make_env()
        transport.script(rst_reply, delay=0.01)
        result = run_trial(clock, transport, scope)
        port = next(p for p in result.ports if p.port == 80)
        self.assertEqual(port.state, CLOSED)
        self.assertEqual(result.closing_rsts_sent, 0)

    def test_no_response_is_filtered_after_exactly_two_attempts(self) -> None:
        scope, clock, transport = make_env()
        result = run_trial(clock, transport, scope)
        self.assertEqual(result.probes_transmitted, 8)  # 4 ports x 2 attempts
        for port in result.ports:
            self.assertEqual(port.state, NO_RESPONSE)
            self.assertEqual(port.attempts_used, 2)
            self.assertEqual(
                [obs.kind for obs in port.observations], ["probe", "probe"]
            )

    def test_resolved_ports_skip_the_second_attempt(self) -> None:
        scope, clock, transport = make_env()
        transport.script(syn_ack, delay=0.01)
        result = run_trial(clock, transport, scope)
        self.assertEqual(result.probes_transmitted, 4)

    def test_second_attempt_recovers_a_slow_first_reply(self) -> None:
        scope, clock, transport = make_env()
        seq1 = sequence_for(0)
        transport.script_when(
            syn_ack, delay=2.0,
            predicate=lambda p: is_syn(p) and int(p[TCP].seq) == seq1,
        )
        transport.script_when(
            syn_ack, delay=0.01,
            predicate=lambda p: is_syn(p) and int(p[TCP].seq) == seq1 + 4096,
        )
        result = run_trial(clock, transport, scope)
        port = next(p for p in result.ports if p.port == 22)
        self.assertEqual(port.state, OPEN)
        self.assertEqual(port.attempts_used, 2)

    def test_duplicate_syn_ack_is_counted_but_not_reclassified(self) -> None:
        scope, clock, transport = make_env()
        transport.script(syn_ack, delay=0.01)
        transport.script(syn_ack, delay=0.90)  # a late retransmission
        result = run_trial(clock, transport, scope)
        port = next(p for p in result.ports if p.port == 443)
        replies = [obs for obs in port.observations if obs.kind == "syn-ack"]
        self.assertEqual(len(replies), 2)
        self.assertEqual(
            [obs.duplicate for obs in replies], [False, True]
        )
        self.assertEqual(port.state, OPEN)


    def test_tail_gap_syn_ack_is_classified_and_closed(self) -> None:
        """A reply arriving after the final receive window but before the
        capture stops is still a genuine observation: classify it open and
        close the exchange with an RST."""
        scope, clock, transport = make_env()
        transport.script(syn_ack, delay=2.0)  # later than the 1.5 s window
        result = run_trial(clock, transport, scope)
        for port in result.ports:
            self.assertEqual(port.state, OPEN)
            self.assertEqual(port.attempts_used, 2)
        self.assertEqual(result.probes_transmitted, 8)
        self.assertEqual(result.closing_rsts_sent, 4)
        rsts = [pkt for pkt in transport.sent if int(pkt[TCP].flags) == 0x04]
        self.assertEqual(len(rsts), 4)


class BoundsTests(unittest.TestCase):
    def test_all_transmissions_respect_the_rate_limit(self) -> None:
        scope, clock, transport = make_env()
        transport.script(syn_ack, delay=0.01)
        engine = ScanEngine(scope, transport, clock=clock,
                            sleeper=clock.advance)
        engine.run_trial()
        # 4 probes + 4 closing RSTs, every frame paced at <= 20 pps
        self.assertEqual(len(transport.sent), 8)
        self.assertEqual(len(transport.sent_at), 8)
        gaps = [
            b - a for a, b in zip(transport.sent_at, transport.sent_at[1:])
        ]
        self.assertTrue(all(gap >= 0.049 for gap in gaps),
                        f"rate limit violated: gaps={gaps}")
        # the four closing RSTs are paced too
        rst_gaps = gaps[4:]
        self.assertTrue(all(gap >= 0.049 for gap in rst_gaps),
                        f"closing RSTs not paced: gaps={rst_gaps}")

    def test_attempts_never_exceed_the_manifest_bound(self) -> None:
        scope, clock, transport = make_env()
        result = run_trial(clock, transport, scope)
        for port in result.ports:
            self.assertLessEqual(port.attempts_used, 2)
        self.assertEqual(result.probes_transmitted, 8)


    def test_rtt_uses_the_captured_wire_time_of_the_probe(self) -> None:
        scope, clock, transport = make_env()
        transport.script(syn_ack, delay=0.01)
        # The capture also sees our own probe leave the wire 3 ms after the
        # Python clock stamped the send.
        transport.script(lambda packet: packet.copy(), delay=0.003, when=is_syn)
        engine = ScanEngine(scope, transport, clock=clock,
                            sleeper=clock.advance)
        trial = engine.run_trial()
        port = next(p for p in trial.ports if p.port == 22)
        reply = next(obs for obs in port.observations if obs.kind == "syn-ack")
        # reply 10 ms after send; the probe was seen on the wire 3 ms after
        # send, so the RTT is 7 ms, not 10 ms.
        self.assertAlmostEqual(
            (reply.received_epoch - reply.sent_epoch) * 1000.0, 7.0, places=3
        )


class ExtensionTests(unittest.TestCase):
    def test_trials_produce_independent_results(self) -> None:
        scope, clock, transport = make_env()
        transport.script(syn_ack, delay=0.01)
        engine = ScanEngine(scope, transport, clock=clock,
                            sleeper=clock.advance)
        trials = engine.run_trials(3)
        self.assertEqual(len(trials), 3)
        for trial in trials:
            self.assertEqual(trial.probes_transmitted, 4)
            self.assertTrue(
                all(port.state == OPEN for port in trial.ports)
            )


if __name__ == "__main__":
    unittest.main()
