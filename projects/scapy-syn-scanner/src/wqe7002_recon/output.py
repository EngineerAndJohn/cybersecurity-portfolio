"""Deterministic result documents.

Every value that leaves this module is computed from the run state with a
fixed key order, sorted ports, fixed-precision floats and UTC ISO-8601
timestamps, so two runs over identical observations produce byte-identical
JSON.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import TOOL_NAME, __version__
from .engine import NO_RESPONSE, Observation, Plan, PortResult, TrialResult
from .probes import sequence_for, source_port_for
from .scope import Scope

RESULT_SCHEMA = "wqe7002-recon-result-v1"


def utc_iso(epoch: float) -> str:
    stamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _round(value: float, digits: int = 3) -> float:
    return round(value + 0.0, digits)


def _observation_doc(obs: "Observation") -> dict[str, Any]:
    doc: dict[str, Any] = {"kind": obs.kind, "attempt": obs.attempt}
    if obs.sent_epoch is not None:
        doc["sent_utc"] = utc_iso(obs.sent_epoch)
    if obs.received_epoch is not None:
        doc["received_utc"] = utc_iso(obs.received_epoch)
        doc["rtt_ms"] = _round((obs.received_epoch - obs.sent_epoch) * 1000.0)
    if obs.icmp_code is not None:
        doc["icmp_code"] = obs.icmp_code
    doc["duplicate"] = obs.duplicate
    return doc


def _port_doc(port_result: "PortResult") -> dict[str, Any]:
    return {
        "port": port_result.port,
        "state": port_result.state,
        "attempts_used": port_result.attempts_used,
        "observations": [
            _observation_doc(obs) for obs in port_result.observations
        ],
    }


def _classification_attempt(port_result: "PortResult") -> int:
    """Attempt whose probe earned the definitive classification (0 if none)."""
    for obs in port_result.observations:
        if obs.kind != "probe" and not obs.duplicate:
            return obs.attempt
    return 0


def _parameters_doc(scope: Scope) -> dict[str, Any]:
    per_port: dict[str, Any] = {}
    for index, port in enumerate(scope.ports):
        per_port[str(port)] = {
            "source_port": source_port_for(index),
            "sequences": [
                sequence_for(index) + (attempt - 1) * 4096
                for attempt in range(1, scope.maximum_attempts + 1)
            ],
        }
    return {
        "target": scope.target,
        "interface": scope.interface,
        "ports": list(scope.ports),
        "maximum_rate_pps": scope.maximum_rate_pps,
        "maximum_attempts": scope.maximum_attempts,
        "timeout_seconds": scope.timeout_seconds,
        "probe_parameters_per_port": per_port,
    }


def _summary_doc(trials: list[TrialResult]) -> dict[str, Any]:
    """Cross-trial stability and retry statistics (the evaluated extension)."""
    per_port: dict[int, dict[str, Any]] = {}
    for trial in trials:
        for port_result in trial.ports:
            entry = per_port.setdefault(
                port_result.port,
                {
                    "outcomes": {},
                    "attempts_used_total": 0,
                    "second_attempt_recoveries": 0,
                    "rtt_ms_first_replies": [],
                },
            )
            state = port_result.state
            entry["outcomes"][state] = entry["outcomes"].get(state, 0) + 1
            entry["attempts_used_total"] += port_result.attempts_used
            if (
                port_result.state != NO_RESPONSE
                and _classification_attempt(port_result) == 2
            ):
                entry["second_attempt_recoveries"] += 1
            for obs in port_result.observations:
                if obs.kind == "syn-ack" and not obs.duplicate:
                    entry["rtt_ms_first_replies"].append(
                        _round((obs.received_epoch - obs.sent_epoch) * 1000.0)
                    )

    port_summaries = []
    for port in sorted(per_port):
        entry = per_port[port]
        rtts = entry["rtt_ms_first_replies"]
        stats: dict[str, Any] = {"count": len(rtts)}
        if rtts:
            stats.update(
                {
                    "mean": _round(sum(rtts) / len(rtts)),
                    "min": _round(min(rtts)),
                    "max": _round(max(rtts)),
                }
            )
        port_summaries.append(
            {
                "port": port,
                "outcomes": {
                    state: entry["outcomes"][state]
                    for state in sorted(entry["outcomes"])
                },
                "attempts_used_total": entry["attempts_used_total"],
                "second_attempt_recoveries": entry[
                    "second_attempt_recoveries"
                ],
                "rtt_ms": stats,
            }
        )

    retry_probes = 0
    for trial in trials:
        for port_result in trial.ports:
            retry_probes += max(0, port_result.attempts_used - 1)
    return {
        "trials": len(trials),
        "retry_probes_sent": retry_probes,
        "second_attempt_recoveries_total": sum(
            item["second_attempt_recoveries"] for item in port_summaries
        ),
        "per_port": port_summaries,
    }


def build_result_document(
    scope: Scope, trials: list[TrialResult]
) -> dict[str, Any]:
    """Assemble the canonical result document for one executed run.

    The top-level window and counters describe the *whole* executed command:
    when ``--trials N`` repeats the scan, ``probes_transmitted`` and
    ``closing_rsts_sent`` are totals across all N trials, so the top level
    always matches what the capture shows on the wire.
    """
    first = trials[0]
    document: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "option": "tcp-syn-scan",
        "scope_id": scope.scope_id,
        "window": {
            "started_utc": utc_iso(first.started_epoch),
            "finished_utc": utc_iso(trials[-1].finished_epoch),
        },
        "parameters": _parameters_doc(scope),
        "probes_transmitted": sum(t.probes_transmitted for t in trials),
        "closing_rsts_sent": sum(t.closing_rsts_sent for t in trials),
        "results": [_port_doc(port) for port in first.ports],
    }
    if len(trials) > 1:
        document["trials"] = [
            {
                "trial": index + 1,
                "window": {
                    "started_utc": utc_iso(trial.started_epoch),
                    "finished_utc": utc_iso(trial.finished_epoch),
                },
                "probes_transmitted": trial.probes_transmitted,
                "closing_rsts_sent": trial.closing_rsts_sent,
                "results": [_port_doc(port) for port in trial.ports],
            }
            for index, trial in enumerate(trials)
        ]
        document["summary"] = _summary_doc(trials)
    return document


def write_json(path: str | Path, document: dict[str, Any]) -> None:
    """Write the document with a fixed serialisation; deterministic bytes."""
    payload = json.dumps(document, indent=2, ensure_ascii=True) + "\n"
    Path(path).write_text(payload, encoding="utf-8")


def render_plan(plan: Plan, scope_id: str) -> str:
    lines = [
        f"plan for scope {scope_id}",
        f"  target:            {plan.target}",
        f"  interface:         {plan.interface}",
        f"  ports:             {', '.join(str(p) for p in plan.ports)}",
        f"  rate:              {plan.rate_pps} probes/second (max)",
        f"  attempts:          {plan.attempts} per port (max)",
        f"  timeout:           {plan.timeout_seconds} s per attempt",
        f"  worst-case probes: {len(plan.schedule)}",
    ]
    lines.append("  schedule (port, attempt, source-port, sequence):")
    for port, attempt, sport, seq in plan.schedule:
        lines.append(f"    {port:>5}  attempt {attempt}  sport {sport}  seq {seq}")
    return "\n".join(lines) + "\n"
