"""CLI contract: exit codes, plan-by-default, execute flag, output writing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wqe7002_recon.cli import (
    EXIT_EXECUTION_FAILURE,
    EXIT_INVALID,
    EXIT_OK,
    main,
)
from wqe7002_recon.engine import Observation, PortResult, TrialResult

from tests.support import STANDARD_SCOPE_JSON, standard_scope_path, write_scope_file


def _stub_engine_result() -> TrialResult:
    return TrialResult(
        ports=[
            PortResult(port=22, state="open", attempts_used=1,
                       observations=[
                           Observation(attempt=1, kind="probe",
                                       sent_epoch=1_700_000_000.0),
                           Observation(attempt=1, kind="syn-ack",
                                       sent_epoch=1_700_000_000.0,
                                       received_epoch=1_700_000_000.01),
                       ]),
            PortResult(port=80, state="filtered-or-no-response",
                       attempts_used=2,
                       observations=[
                           Observation(attempt=1, kind="probe",
                                       sent_epoch=1_700_000_000.0),
                           Observation(attempt=2, kind="probe",
                                       sent_epoch=1_700_001_500.0),
                       ]),
        ],
        probes_transmitted=3,
        closing_rsts_sent=1,
        started_epoch=1_700_000_000.0,
        finished_epoch=1_700_001_500.0,
    )


class ExitCodeTests(unittest.TestCase):
    def test_invalid_scope_returns_exit_2_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad_scope = write_scope_file('{"not": "a scope"}')
            output = str(Path(directory) / "result.json")
            self.assertEqual(
                main(["--scope", bad_scope, "--output", output]),
                EXIT_INVALID,
            )
            self.assertFalse(Path(output).exists())

    def test_trials_requires_execute(self) -> None:
        scope = standard_scope_path()
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / "result.json")
            self.assertEqual(
                main(["--scope", scope, "--output", output, "--trials", "3"]),
                EXIT_INVALID,
            )
            self.assertFalse(Path(output).exists())

    def test_out_of_range_trials_is_rejected(self) -> None:
        scope = standard_scope_path()
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / "result.json")
            self.assertEqual(
                main(["--scope", scope, "--output", output,
                      "--execute", "--trials", "0"]),
                EXIT_INVALID,
            )
            self.assertEqual(
                main(["--scope", scope, "--output", output,
                      "--execute", "--trials", "11"]),
                EXIT_INVALID,
            )

    def test_plan_mode_returns_zero_and_writes_nothing(self) -> None:
        scope = standard_scope_path()
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / "result.json")
            self.assertEqual(
                main(["--scope", scope, "--output", output]), EXIT_OK
            )
            self.assertFalse(Path(output).exists())

    def test_version_flag(self) -> None:
        self.assertEqual(main(["--version"]), EXIT_OK)


class ExecuteTests(unittest.TestCase):
    def test_execute_writes_the_result_document(self) -> None:
        scope = standard_scope_path()
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / "result.json")
            with mock.patch(
                "wqe7002_recon.cli.ScapyTransport"
            ) as transport_class, mock.patch(
                "wqe7002_recon.cli.ScanEngine"
            ) as engine_class:
                transport_class.return_value = mock.Mock()
                engine = engine_class.return_value
                engine.run_trials.return_value = [_stub_engine_result()]
                status = main(
                    ["--scope", scope, "--output", output, "--execute"]
                )
            self.assertEqual(status, EXIT_OK)
            self.assertTrue(Path(output).exists())

    def test_execution_failure_returns_exit_3_and_writes_nothing(self) -> None:
        scope = standard_scope_path()
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / "result.json")
            with mock.patch(
                "wqe7002_recon.cli.ScapyTransport",
                side_effect=PermissionError("no NET_RAW capability"),
            ):
                status = main(
                    ["--scope", scope, "--output", output, "--execute"]
                )
            self.assertEqual(status, EXIT_EXECUTION_FAILURE)
            self.assertFalse(Path(output).exists())


if __name__ == "__main__":
    unittest.main()
