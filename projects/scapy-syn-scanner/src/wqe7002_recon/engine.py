"""Scan orchestration: pacing, attempts, capture windows and classification.

The engine does not touch the network directly: it works through a transport
and a clock.  The real run uses a Scapy transport and the system clock; the
test suite injects a fake transport and a fake clock so every behaviour,
including the rate limit and the second attempt, is exercised without
sending a single packet.
"""

from __future__ import annotations

import time as _time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from scapy.packet import Packet  # type: ignore

from .matcher import (
    ICMP_KIND,
    RST_KIND,
    SYN_ACK_KIND,
    Match,
    ProbeRecord,
    match_own_probe,
    match_reply,
)
from .probes import (
    build_closing_rst,
    build_syn_probe,
    sequence_for,
    source_port_for,
)
from .scope import Scope

OPEN = "open"
CLOSED = "closed"
ICMP_STATE = "filtered-icmp-unreachable"
NO_RESPONSE = "filtered-or-no-response"


class ScanExecutionError(RuntimeError):
    """A failure that prevents a meaningful run (exit status 3)."""


class Clock(Protocol):
    def time(self) -> float: ...  # epoch seconds, UTC, for timestamps

    def monotonic(self) -> float: ...  # pacing clock


class Transport(Protocol):
    """Packet I/O boundary.  The fake implementation records sends and
    replays scripted captures; the real one drives Scapy on the interface."""

    our_ip: str
    our_mac: str
    target_mac: str

    def resolve_target_mac(self) -> None: ...

    def start_capture(self) -> None: ...

    def drain_captured(self) -> list[tuple[float, Packet]]: ...

    def stop_capture(self) -> list[tuple[float, Packet]]: ...

    def send(self, packet: Packet) -> None: ...


class SystemClock:
    def time(self) -> float:
        return _time.time()

    def monotonic(self) -> float:
        return _time.monotonic()


class PaceGate:
    """Enforces a hard inter-transmission gap of ``1 / pps`` seconds.

    Applies to every frame the tool transmits, probes and closing RSTs
    alike, so the whole run stays within the manifest's rate bound.
    """

    def __init__(
        self,
        pps: int,
        clock: Clock,
        sleeper: Callable[[float], None],
    ) -> None:
        if pps < 1:
            raise ValueError("pps must be >= 1")
        self._gap = 1.0 / pps
        self._clock = clock
        self._sleeper = sleeper
        self._next: Optional[float] = None

    def wait(self) -> float:
        """Block until the next transmission is allowed; return the monotonic
        time at which it becomes allowed."""
        now = self._clock.monotonic()
        if self._next is not None:
            remaining = self._next - now
            if remaining > 0:
                self._sleeper(remaining)
                now = self._clock.monotonic()
            if now < self._next:  # coarse sleepers may under-sleep
                now = self._next
        self._next = now + self._gap
        return now


@dataclass
class Observation:
    """One transmitted probe or one received reply."""

    attempt: int
    kind: str  # "probe", "syn-ack", "rst", "icmp-unreachable"
    sent_epoch: Optional[float] = None
    received_epoch: Optional[float] = None
    icmp_code: Optional[int] = None
    duplicate: bool = False


@dataclass
class PortResult:
    port: int
    state: str = NO_RESPONSE
    attempts_used: int = 0
    observations: list[Observation] = field(default_factory=list)


@dataclass
class TrialResult:
    ports: list[PortResult]
    probes_transmitted: int
    closing_rsts_sent: int
    started_epoch: float
    finished_epoch: float


@dataclass(frozen=True)
class Plan:
    """The full probe schedule, computable without touching the network."""

    target: str
    interface: str
    ports: tuple[int, ...]
    rate_pps: int
    attempts: int
    timeout_seconds: float
    schedule: tuple[tuple[int, int, int, int], ...]  # (port, attempt, sport, seq)


def build_plan(scope: Scope) -> Plan:
    """Compute the full probe schedule without touching the network."""
    schedule: list[tuple[int, int, int, int]] = []
    for index, port in enumerate(scope.ports):
        for attempt in range(1, scope.maximum_attempts + 1):
            schedule.append(
                (
                    port,
                    attempt,
                    source_port_for(index),
                    sequence_for(index) + (attempt - 1) * 4096,
                )
            )
    return Plan(
        target=scope.target,
        interface=scope.interface,
        ports=scope.ports,
        rate_pps=scope.maximum_rate_pps,
        attempts=scope.maximum_attempts,
        timeout_seconds=scope.timeout_seconds,
        schedule=tuple(schedule),
    )


class ScanEngine:
    def __init__(
        self,
        scope: Scope,
        transport: Transport,
        clock: Clock = SystemClock(),
        sleeper: Callable[[float], None] = _time.sleep,
    ) -> None:
        self.scope = scope
        self.transport = transport
        self.clock = clock
        self.sleeper = sleeper
        self.pacer = PaceGate(scope.maximum_rate_pps, clock, sleeper)

    # ---------------------------------------------------------------- trials

    def _prepare_registry(self) -> dict[int, dict[int, ProbeRecord]]:
        registry: dict[int, dict[int, ProbeRecord]] = {}
        for index, port in enumerate(self.scope.ports):
            sport = source_port_for(index)
            registry[sport] = {
                attempt: ProbeRecord(
                    port=port,
                    source_port=sport,
                    sequence=sequence_for(index) + (attempt - 1) * 4096,
                    attempt=attempt,
                )
                for attempt in range(1, self.scope.maximum_attempts + 1)
            }
        return registry

    def _send_probe(self, record: ProbeRecord) -> float:
        self.pacer.wait()
        sent_epoch = self.clock.time()
        probe = build_syn_probe(
            target_ip=self.scope.target,
            source_ip=self.transport.our_ip,
            source_mac=self.transport.our_mac,
            target_mac=self.transport.target_mac,
            source_port=record.source_port,
            sequence=record.sequence,
            destination_port=record.port,
        )
        self.transport.send(probe)
        return sent_epoch

    def _send_closing_rst(self, record: ProbeRecord, match: Match) -> None:
        assert match.syn_ack_ack is not None
        self.pacer.wait()
        rst = build_closing_rst(
            target_ip=self.scope.target,
            source_ip=self.transport.our_ip,
            source_mac=self.transport.our_mac,
            target_mac=self.transport.target_mac,
            source_port=record.source_port,
            destination_port=record.port,
            syn_ack_seq=match.syn_ack_seq or 0,
            syn_ack_ack=match.syn_ack_ack,
        )
        self.transport.send(rst)

    def run_trial(self) -> TrialResult:
        """Execute one bounded scan and classify the replies live.

        Replies are dispatched as they arrive during each attempt's receive
        window, so ports resolved by attempt 1 are never probed again, and
        every SYN/ACK exchange is closed with an RST before the next attempt
        begins.  The closing RSTs are sent while the capture is still
        running, so they appear in the recorded exchange.
        """
        registry = self._prepare_registry()
        port_order = list(self.scope.ports)

        sent: dict[int, list[Observation]] = {p: [] for p in port_order}
        sent_epochs: dict[tuple[int, int], float] = {}
        first_match: dict[int, Match] = {}
        rst_sent: set[int] = set()
        probes_transmitted = 0
        closing_rsts_sent = 0

        def dispatch(epoch: float, packet: Packet) -> None:
            nonlocal closing_rsts_sent
            own_probe = match_own_probe(
                packet,
                registry,
                self.scope.target,
                self.transport.our_ip,
                self.transport.our_mac,
            )
            if own_probe is not None:
                # Replace the Python-clock send time with the capture's wire
                # time for this probe, so RTTs use a single clock.
                sent_epochs[(own_probe.port, own_probe.attempt)] = epoch
                for obs in sent[own_probe.port]:
                    if obs.kind == "probe" and obs.attempt == own_probe.attempt:
                        obs.sent_epoch = epoch
                return
            match = match_reply(
                packet,
                registry,
                self.scope.target,
                self.transport.our_ip,
                self.transport.our_mac,
            )
            if match is None:
                return
            port = match.probe.port
            duplicate = first_match.get(port) is not None
            observation = Observation(
                attempt=match.probe.attempt,
                kind=match.kind,
                sent_epoch=sent_epochs.get(
                    (port, match.probe.attempt)
                ),
                received_epoch=epoch,
                icmp_code=match.icmp_code,
                duplicate=duplicate,
            )
            sent[port].append(observation)
            if not duplicate:
                first_match[port] = match

        started_epoch = self.clock.time()
        self.transport.start_capture()
        try:
            self.transport.resolve_target_mac()
            for attempt in range(1, self.scope.maximum_attempts + 1):
                pending = [
                    port for port in port_order
                    if first_match.get(port) is None
                ]
                if not pending:
                    break
                for port in pending:
                    record = registry[
                        source_port_for(port_order.index(port))
                    ][attempt]
                    sent_epoch = self._send_probe(record)
                    probes_transmitted += 1
                    sent_epochs[(port, attempt)] = sent_epoch
                    sent[port].append(
                        Observation(
                            attempt=attempt, kind="probe",
                            sent_epoch=sent_epoch,
                        )
                    )
                deadline = self.clock.monotonic() + self.scope.timeout_seconds
                while True:
                    for epoch, packet in self.transport.drain_captured():
                        dispatch(epoch, packet)
                    remaining = deadline - self.clock.monotonic()
                    if remaining <= 0:
                        break
                    self.sleeper(min(remaining, 0.05))
                for port in pending:
                    match = first_match.get(port)
                    if match is not None and match.kind == SYN_ACK_KIND:
                        self._send_closing_rst(match.probe, match)
                        closing_rsts_sent += 1
                        rst_sent.add(port)
        finally:
            captured = self.transport.stop_capture()
        for epoch, packet in captured:
            dispatch(epoch, packet)
        # A reply that arrives in the tail gap between the final deadline and
        # stop_capture is still a genuine observation: classify it (dispatch
        # above) and, if it was a SYN/ACK, close the exchange now.
        for port in port_order:
            match = first_match.get(port)
            if (
                match is not None
                and match.kind == SYN_ACK_KIND
                and port not in rst_sent
            ):
                self._send_closing_rst(match.probe, match)
                closing_rsts_sent += 1
                rst_sent.add(port)

        results: list[PortResult] = []
        for port in port_order:
            observations = sorted(
                sent[port],
                key=lambda obs: (
                    obs.received_epoch
                    if obs.received_epoch is not None
                    else obs.sent_epoch or 0.0,
                ),
            )
            match = first_match.get(port)
            state = {
                SYN_ACK_KIND: OPEN,
                RST_KIND: CLOSED,
                ICMP_KIND: ICMP_STATE,
            }.get(match.kind if match else "", NO_RESPONSE)
            results.append(
                PortResult(
                    port=port,
                    state=state,
                    attempts_used=sum(
                        1 for obs in observations if obs.kind == "probe"
                    ),
                    observations=observations,
                )
            )

        return TrialResult(
            ports=results,
            probes_transmitted=probes_transmitted,
            closing_rsts_sent=closing_rsts_sent,
            started_epoch=started_epoch,
            finished_epoch=self.clock.time(),
        )

    def run_trials(self, trials: int) -> list[TrialResult]:
        """Repeat the bounded scan ``trials`` times (the evaluated extension)."""
        if trials < 1:
            raise ValueError("trials must be >= 1")
        return [self.run_trial() for _ in range(trials)]
