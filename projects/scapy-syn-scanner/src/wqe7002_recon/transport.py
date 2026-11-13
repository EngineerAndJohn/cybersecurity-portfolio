"""Packet I/O.

``ScapyTransport`` performs the only live network operations in this tool:
one ARP resolution, raw sends on the authorised interface, and a passive
capture of the interface's own exchange.  ``FakeTransport`` replays scripted
traffic for tests and never touches the network.
"""

from __future__ import annotations

import time as _time
from typing import Callable, Optional

from scapy.all import (  # type: ignore
    ARP,
    AsyncSniffer,
    Ether,
    get_if_addr,
    get_if_hwaddr,
    sendp,
    srp1,
)
from scapy.packet import Packet  # type: ignore

from .engine import ScanExecutionError
from .probes import build_arp_who_has

CAPTURE_FILTER = "arp or (ip and (tcp or icmp))"


class ScapyTransport:
    def __init__(self, interface: str, target_ip: str) -> None:
        self.interface = interface
        self.target_ip = target_ip
        try:
            self.our_ip = get_if_addr(interface)
            self.our_mac = get_if_hwaddr(interface).lower()
        except Exception as error:  # noqa: BLE001; Scapy raises assorted
            raise ScanExecutionError(
                f"cannot read address information for interface "
                f"{interface!r}: {error}"
            ) from error
        if not self.our_ip or self.our_ip == "0.0.0.0":
            raise ScanExecutionError(
                f"interface {interface!r} has no IPv4 address; the scope "
                "requires the scanner interface to be addressed"
            )
        self.target_mac = ""
        self._sniffer: Optional[AsyncSniffer] = None
        self._seen = 0

    def resolve_target_mac(self) -> None:
        """Resolve the target's MAC once, before any probe is sent."""
        request = build_arp_who_has(
            target_ip=self.target_ip,
            source_ip=self.our_ip,
            source_mac=self.our_mac,
        )
        reply = srp1(request, iface=self.interface, timeout=2, verbose=0)
        if reply is None or not reply.haslayer(ARP) or int(reply[ARP].op) != 2:
            raise ScanExecutionError(
                f"no ARP reply for authorised target {self.target_ip} on "
                f"interface {self.interface}; is the lab host reachable?"
            )
        self.target_mac = str(reply[ARP].hwsrc)

    def start_capture(self) -> None:
        if self._sniffer is not None:
            raise ScanExecutionError("capture already started")
        # Scapy's AsyncSniffer.results only materialises at stop(), so live
        # dispatch collects packets through a prn callback into our own list.
        self._live: list[Packet] = []
        sniffer = AsyncSniffer(
            iface=self.interface,
            store=False,
            prn=self._live.append,
            filter=CAPTURE_FILTER,
        )
        sniffer.start()
        deadline = _time.monotonic() + 5.0
        while not sniffer.running and _time.monotonic() < deadline:
            _time.sleep(0.02)
        if not sniffer.running:
            sniffer.stop()
            raise ScanExecutionError(
                f"capture failed to attach to interface {self.interface!r}"
            )
        _time.sleep(0.1)  # let libpcap finish attaching before the first probe
        self._sniffer = sniffer

    def drain_captured(self) -> list[tuple[float, Packet]]:
        """Packets captured since the last drain (live dispatch)."""
        if self._sniffer is None:
            raise ScanExecutionError("no capture is running")
        new = self._live[self._seen:]
        self._seen = len(self._live)
        return [(float(packet.time), packet) for packet in new]

    def stop_capture(self) -> list[tuple[float, Packet]]:
        if self._sniffer is None:
            raise ScanExecutionError("no capture is running")
        self._sniffer.stop()
        remainder = self._live[self._seen:]
        self._sniffer = None
        self._seen = 0
        return [(float(packet.time), packet) for packet in remainder]

    def send(self, packet: Packet) -> None:
        sendp(packet, iface=self.interface, verbose=False)


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------

FakeReply = Callable[[Packet], Packet]
FakeDelay = Callable[[Packet], Optional[float]]


def _is_syn(packet: Packet) -> bool:
    from scapy.all import TCP  # type: ignore

    tcp = packet.getlayer(TCP)
    return tcp is not None and int(tcp.flags) & 0x02


class FakeClock:
    """A clock the tests drive by hand."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self._now = start

    def time(self) -> float:
        return self._now

    def monotonic(self) -> float:
        return self._now

    def advance(self, delta: float) -> None:
        if delta < 0:
            raise ValueError("time cannot run backwards in tests")
        self._now += delta


class FakeTransport:
    """Records sends and hands back scripted replies at scripted delays."""

    def __init__(
        self,
        our_ip: str = "172.28.70.2",
        our_mac: str = "02:42:ac:1c:46:02",
        target_mac: str = "02:42:ac:1c:46:0a",
        clock: Optional[FakeClock] = None,
    ) -> None:
        self.our_ip = our_ip
        self.our_mac = our_mac
        self.target_mac = target_mac
        self.target_resolved = False
        self.clock = clock if clock is not None else FakeClock()
        self.sent: list[Packet] = []
        self.sent_at: list[float] = []
        self.capture_log: list[tuple[float, Packet]] = []
        self.scripted: list[tuple[FakeDelay, FakeReply]] = []
        self.started = False
        self._drained = 0

    # -- Transport interface ----------------------------------------------
    def resolve_target_mac(self) -> None:
        self.target_resolved = True

    def start_capture(self) -> None:
        self.started = True

    def _eligible(self) -> list[tuple[float, Packet]]:
        return [
            entry for entry in self.capture_log if entry[0] <= self.clock.time()
        ]

    def drain_captured(self) -> list[tuple[float, Packet]]:
        eligible = self._eligible()
        new = eligible[self._drained:]
        self._drained = len(eligible)
        return new

    def stop_capture(self) -> list[tuple[float, Packet]]:
        self.started = False
        # The real capture returns every frame that arrived before it was
        # stopped, including ones that missed the receive windows; the fake
        # mirrors that instead of filtering by the clock again.
        return self.capture_log[self._drained:]

    def send(self, packet: Packet) -> None:
        self.sent.append(packet)
        self.sent_at.append(self.clock.time())
        for delay_fn, build in self.scripted:
            delay = delay_fn(packet)
            if delay is None or delay < 0:
                continue
            reply = build(packet)
            self.capture_log.append((self.clock.time() + delay, reply))
            self.capture_log.sort(key=lambda entry: entry[0])

    # -- Test helpers --------------------------------------------------------
    def script(
        self,
        build: FakeReply,
        delay: float = 0.01,
        when: Optional[Callable[[Packet], bool]] = None,
    ) -> None:
        """Reply to every probe with ``build`` after ``delay`` seconds.

        By default the script fires only for SYN probes, so closing RSTs do
        not trigger it; pass ``when`` for any other behaviour.
        """
        predicate = when if when is not None else _is_syn
        self.scripted.append(
            (
                lambda packet: delay if predicate(packet) else None,
                build,
            )
        )

    def script_when(
        self, build: FakeReply, delay: float, predicate: Callable[[Packet], bool]
    ) -> None:
        def conditional_delay(packet: Packet) -> Optional[float]:
            return delay if predicate(packet) else None

        self.scripted.append((conditional_delay, build))

    def inject(self, packet: Packet, at_epoch: Optional[float] = None) -> None:
        epoch = self.clock.time() if at_epoch is None else at_epoch
        self.capture_log.append((epoch, packet))
        self.capture_log.sort(key=lambda entry: entry[0])
