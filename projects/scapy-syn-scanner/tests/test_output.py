"""Deterministic result documents and the trials summary."""

from __future__ import annotations

import json
import unittest

from scapy.all import TCP  # type: ignore

from wqe7002_recon.engine import ScanEngine
from wqe7002_recon.output import (
    RESULT_SCHEMA,
    build_result_document,
    render_plan,
    write_json,
)
from wqe7002_recon.engine import build_plan

from tests.support import is_syn, make_env, syn_ack


def run_document(scripted: bool = True, trials: int = 1):
    scope, clock, transport = make_env()
    if scripted:
        transport.script(syn_ack, delay=0.01)
    engine = ScanEngine(scope, transport, clock=clock,
                        sleeper=clock.advance)
    results = engine.run_trials(trials)
    return scope, build_result_document(scope, results)


class SchemaTests(unittest.TestCase):
    def test_document_records_window_scope_parameters_and_results(self) -> None:
        scope, document = run_document()
        self.assertEqual(document["schema"], RESULT_SCHEMA)
        self.assertEqual(document["tool"]["name"], "wqe7002-recon")
        self.assertEqual(document["tool"]["version"], "1.0.0")
        self.assertEqual(document["option"], "tcp-syn-scan")
        self.assertEqual(document["scope_id"],
                         "wqe7002-a1-standard-tcp-syn-scan-v1")
        window = document["window"]
        self.assertTrue(window["started_utc"].endswith("Z"))
        self.assertLessEqual(window["started_utc"], window["finished_utc"])
        parameters = document["parameters"]
        self.assertEqual(parameters["target"], "172.28.70.10")
        self.assertEqual(parameters["interface"], "eth0")
        self.assertEqual(parameters["ports"], [22, 80, 443, 8080])
        self.assertEqual(parameters["maximum_rate_pps"], 20)
        self.assertEqual(parameters["maximum_attempts"], 2)
        self.assertEqual(parameters["timeout_seconds"], 1.5)
        self.assertEqual(len(document["results"]), 4)

    def test_open_port_observations_carry_utc_times_and_rtt(self) -> None:
        _, document = run_document()
        port22 = document["results"][0]
        self.assertEqual(port22["port"], 22)
        self.assertEqual(port22["state"], "open")
        observations = port22["observations"]
        self.assertEqual(observations[0]["kind"], "probe")
        self.assertEqual(observations[1]["kind"], "syn-ack")
        self.assertFalse(observations[1]["duplicate"])
        self.assertIn("sent_utc", observations[0])
        self.assertIn("received_utc", observations[1])
        self.assertIn("rtt_ms", observations[1])

    def test_no_response_state_is_named_exactly_as_the_brief_requires(
        self,
    ) -> None:
        _, document = run_document(scripted=False)
        for port in document["results"]:
            self.assertEqual(port["state"], "filtered-or-no-response")
            self.assertEqual(port["attempts_used"], 2)

    def test_ports_appear_in_ascending_order(self) -> None:
        _, document = run_document()
        ports = [port["port"] for port in document["results"]]
        self.assertEqual(ports, sorted(ports))


class DeterminismTests(unittest.TestCase):
    def test_two_identical_runs_produce_byte_identical_json(self) -> None:
        first_scope, first_doc = run_document()
        second_scope, second_doc = run_document()
        self.assertEqual(first_scope.scope_id, second_scope.scope_id)
        first_bytes = json.dumps(first_doc, indent=2) + "\n"
        second_bytes = json.dumps(second_doc, indent=2) + "\n"
        self.assertEqual(first_bytes, second_bytes)

    def test_plan_rendering_is_deterministic(self) -> None:
        scope, _, _ = make_env()
        self.assertEqual(render_plan(build_plan(scope), scope.scope_id),
                         render_plan(build_plan(scope), scope.scope_id))


class TrialsSummaryTests(unittest.TestCase):
    def test_summary_reports_stability_and_retry_metrics(self) -> None:
        _, document = run_document(trials=5)
        self.assertEqual(len(document["trials"]), 5)
        summary = document["summary"]
        self.assertEqual(summary["trials"], 5)
        self.assertEqual(summary["retry_probes_sent"], 0)
        self.assertEqual(summary["second_attempt_recoveries_total"], 0)
        per_port = summary["per_port"]
        self.assertEqual(len(per_port), 4)
        self.assertEqual(per_port[0]["port"], 22)
        self.assertEqual(per_port[0]["outcomes"], {"open": 5})
        rtt = per_port[0]["rtt_ms"]
        self.assertEqual(rtt["count"], 5)
        self.assertGreaterEqual(rtt["max"], rtt["min"])

    def test_top_level_counters_are_totals_across_all_trials(self) -> None:
        _, document = run_document(trials=3)
        per_trial = document["trials"]
        self.assertEqual(
            document["probes_transmitted"],
            sum(t["probes_transmitted"] for t in per_trial),
        )
        self.assertEqual(
            document["closing_rsts_sent"],
            sum(t["closing_rsts_sent"] for t in per_trial),
        )
        self.assertEqual(document["probes_transmitted"], 12)  # 3 x 4 probes
        self.assertEqual(document["closing_rsts_sent"], 12)

    def test_summary_counts_second_attempt_recovery_end_to_end(self) -> None:
        """Feed a slow first reply through run_trials into the summary and
        check the recovery counter becomes non-zero (the extension's central
        measurement, end to end)."""
        from wqe7002_recon.probes import sequence_for

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
        engine = ScanEngine(scope, transport, clock=clock,
                            sleeper=clock.advance)
        trials = engine.run_trials(2)
        document = build_result_document(scope, trials)
        summary = document["summary"]
        self.assertGreaterEqual(summary["second_attempt_recoveries_total"], 2)
        port22 = next(p for p in summary["per_port"] if p["port"] == 22)
        self.assertEqual(port22["second_attempt_recoveries"], 2)
        self.assertEqual(port22["outcomes"], {"open": 2})

    def test_write_json_ends_with_a_newline(self) -> None:
        import tempfile
        from pathlib import Path

        _, document = run_document()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "result.json"
            write_json(target, document)
            payload = target.read_text(encoding="utf-8")
            self.assertTrue(payload.endswith("\n"))
            self.assertEqual(json.loads(payload)["schema"], RESULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
