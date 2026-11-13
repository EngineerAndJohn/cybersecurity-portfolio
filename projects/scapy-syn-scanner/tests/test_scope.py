"""Scope validation: the manifest is the only source of targeting truth."""

from __future__ import annotations

import json
import unittest

from wqe7002_recon.scope import ScopeError, load_scope

from tests.support import STANDARD_SCOPE_JSON, standard_scope, write_scope_file


def mutated_scope(**changes) -> str:
    document = json.loads(STANDARD_SCOPE_JSON)
    document.update(changes)
    return write_scope_file(json.dumps(document))


class StandardScopeTests(unittest.TestCase):
    def test_standard_scope_parses_with_declared_parameters(self) -> None:
        scope = standard_scope()
        self.assertEqual(scope.target, "172.28.70.10")
        self.assertEqual(scope.ports, (22, 80, 443, 8080))
        self.assertEqual(scope.maximum_rate_pps, 20)
        self.assertEqual(scope.maximum_attempts, 2)
        self.assertEqual(scope.timeout_seconds, 1.5)
        self.assertEqual(scope.interface, "eth0")
        self.assertEqual(scope.scope_id, "wqe7002-a1-standard-tcp-syn-scan-v1")

    def test_ports_are_returned_sorted(self) -> None:
        scope = load_scope(mutated_scope(ports=[8080, 22, 443, 80]))
        self.assertEqual(scope.ports, (22, 80, 443, 8080))


class MalformedScopeTests(unittest.TestCase):
    def test_malformed_json_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(write_scope_file('{"ports": [80, "oops"'))

    def test_missing_required_field_is_rejected(self) -> None:
        stripped = {k: v for k, v in json.loads(STANDARD_SCOPE_JSON).items()
                    if k != "target"}
        with self.assertRaises(ScopeError):
            load_scope(write_scope_file(json.dumps(stripped)))

    def test_placeholder_target_is_rejected(self) -> None:
        for placeholder in ("REPLACE_ME", "<target-ip>", "x.x.x.x", "TODO"):
            with self.assertRaises(ScopeError):
                load_scope(mutated_scope(target=placeholder))

    def test_placeholder_scope_id_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(scope_id="change-me"))

    def test_empty_interface_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(interface=""))

    def test_invalid_target_addresses_are_rejected(self) -> None:
        for bad in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "not-an-ip",
                    "192.0.2.20", "198.51.100.20"):
            with self.assertRaises(ScopeError):
                load_scope(mutated_scope(target=bad))

    def test_device_map_option_is_rejected_by_syn_scanner(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(option="device-map"))

    def test_unknown_schema_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(schema="wqe7002-recon-scope-v2"))


class PortListTests(unittest.TestCase):
    def test_non_integer_port_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(ports=[22, "80", 443]))

    def test_out_of_range_port_is_rejected(self) -> None:
        for bad in (0, 65536, -1):
            with self.assertRaises(ScopeError):
                load_scope(mutated_scope(ports=[22, bad]))

    def test_duplicate_port_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(ports=[22, 22, 80]))

    def test_empty_port_list_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(ports=[]))

    def test_more_than_30_ports_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(ports=list(range(1, 32))))

    def test_boolean_is_not_a_port(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(ports=[22, True]))


class BoundsTests(unittest.TestCase):
    def test_rate_above_20_pps_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(maximum_rate_pps=21))

    def test_zero_rate_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(maximum_rate_pps=0))

    def test_three_attempts_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(maximum_attempts=3))

    def test_nonpositive_timeout_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(timeout_seconds=0))
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(timeout_seconds=-1.5))

    def test_absurd_timeout_is_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(mutated_scope(timeout_seconds=3600))


if __name__ == "__main__":
    unittest.main()
