"""Command-line interface.

Plan mode (the default) validates the scope, prints the complete probe
schedule and transmits nothing.  ``--execute`` is the only path that sends
packets or writes the result file.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from . import TOOL_NAME, __version__
from .engine import ScanEngine, ScanExecutionError, build_plan
from .output import build_result_document, render_plan, write_json
from .scope import ScopeError, load_scope
from .transport import ScapyTransport

EXIT_OK = 0
EXIT_INVALID = 2
EXIT_EXECUTION_FAILURE = 3
MAX_TRIALS = 10


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Bounded Scapy TCP SYN scanner for the WQE7002 course lab. "
            "Plan mode (default) transmits nothing; --execute is the only "
            "flag that sends packets."
        ),
    )
    parser.add_argument(
        "--scope", required=True, metavar="SCOPE.json",
        help="lecturer-issued scope manifest (read-only source of truth)",
    )
    parser.add_argument(
        "--output", required=True, metavar="RESULT.json",
        help="destination for the deterministic result document "
        "(written only with --execute)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--plan", "--dry-run", dest="plan", action="store_true",
        help="validate the scope and print the probe schedule without "
        "transmitting (default behaviour)",
    )
    mode.add_argument(
        "--execute", action="store_true",
        help="explicit execution flag: transmit the bounded probe schedule",
    )
    parser.add_argument(
        "--trials", type=int, default=1, metavar="N",
        help=f"with --execute: repeat the bounded scan N times (1-{MAX_TRIALS}) "
        "and add cross-trial retry/timing statistics to the result document",
    )
    parser.add_argument(
        "--version", action="store_true", help="print the tool version and exit",
    )
    return parser


def _fail(message: str, code: int) -> int:
    print(f"{TOOL_NAME}: error: {message}", file=sys.stderr)
    return code


def main(argv: Optional[Sequence[str]] = None) -> int:
    # --version must work even though --scope/--output are required.
    if argv is not None and "--version" in argv:
        print(f"{TOOL_NAME} {__version__}")
        return EXIT_OK

    args = build_parser().parse_args(argv)

    if args.version:
        print(f"{TOOL_NAME} {__version__}")
        return EXIT_OK

    if args.trials < 1 or args.trials > MAX_TRIALS:
        return _fail(f"--trials must be between 1 and {MAX_TRIALS}", EXIT_INVALID)
    if args.trials > 1 and not args.execute:
        return _fail("--trials requires --execute", EXIT_INVALID)

    try:
        scope = load_scope(args.scope)
    except ScopeError as error:
        return _fail(str(error), EXIT_INVALID)

    if not args.execute:
        # Plan mode: no transport is created, no socket is opened, no packet
        # is built for the wire, and nothing is written to --output.
        print(render_plan(build_plan(scope), scope.scope_id), end="")
        return EXIT_OK

    try:
        transport = ScapyTransport(scope.interface, scope.target)
    except (ScanExecutionError, OSError) as error:
        return _fail(str(error), EXIT_EXECUTION_FAILURE)

    engine = ScanEngine(scope, transport)
    try:
        trials = engine.run_trials(args.trials)
    except Exception as error:  # noqa: BLE001; always fail cleanly
        return _fail(
            f"execution failed: {type(error).__name__}: {error}; "
            "no result file was written",
            EXIT_EXECUTION_FAILURE,
        )

    document = build_result_document(scope, trials)
    try:
        write_json(args.output, document)
    except OSError as error:
        return _fail(
            f"could not write result file {args.output!r}: {error}",
            EXIT_EXECUTION_FAILURE,
        )

    first = trials[0]
    print(
        f"scan complete: {first.probes_transmitted} probes, "
        f"{first.closing_rsts_sent} closing RSTs, "
        f"{len(trials)} trial(s) -> {args.output}"
    )
    for port in first.ports:
        print(f"  port {port.port:<5} {port.state}")
    return EXIT_OK
