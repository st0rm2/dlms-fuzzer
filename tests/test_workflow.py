import io
import sys
import types
import unittest
from unittest.mock import patch

from rich.console import Console

from dlms_enum.config import SecureProfile, parse_config
from dlms_enum.tui import (
    choose_invocation_counter_reuse_test,
    choose_read_plan,
    select_roles,
    verify_counter_source,
)
from dlms_enum.workflow import (
    CounterCandidate,
    PublicPreflight,
    apply_preflight_endpoint,
    run_public_preflight,
    select_counter_source,
)


GAK = "00112233445566778899AABBCCDDEEFF"
GUEK = "FFEEDDCCBBAA99887766554433221100"


class Attribute:
    def __init__(self, index):
        self.index = index


class PublicData:
    objectType = 1
    version = 0
    attributes = [Attribute(2)]
    methodAttributes = []

    def __init__(self, logical_name, description=""):
        self.logicalName = logical_name
        self.description = description

    def getAccess(self, _index):
        return 1

    def getAttributeCount(self):
        return 2


class PreflightSession:
    timeout_changes = []

    def __init__(self, _config, baudrate, _traffic, **kwargs):
        self.baudrate = baudrate
        self.kwargs = kwargs

    def connect(self):
        return {
            "dlms_version": 6,
            "max_receive_pdu_size": 1224,
            "negotiated_conformance": ["get", "multiple_references"],
        }

    def discover_objects(self, _attempt):
        return [
            PublicData("0.0.43.1.0.255", "Invocation counter"),
            PublicData("0.0.96.1.0.255", "Serial number"),
        ]

    def read_meter_identity(self):
        return "METER-1"

    def read_attribute(self, target, _attribute_id, _attempt, **_kwargs):
        value = 1234 if target.logicalName == "0.0.43.1.0.255" else "serial"
        return {"value": value, "dlms_data_type": "unsigned32"}

    def set_response_timeout(self, timeout_ms):
        self.timeout_changes.append(timeout_ms)

    def close(self):
        return []


class PreflightTimeoutSession(PreflightSession):
    def discover_objects(self, _attempt):
        return [PublicData(f"0.0.96.1.{index}.255") for index in range(5)]

    def read_attribute(self, _target, _attribute_id, _attempt, **_kwargs):
        raise TimeoutError("meter did not reply")


class RecordingPreflightSession(PreflightSession):
    client_addresses = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__class__.client_addresses.append(kwargs.get("client_address"))


def multi_role_config():
    secure = {
        "name": "hls_gmac_suite0",
        "role": "client1",
        "client_address": 1,
        "client_system_title": "hex:4D45544552303031",
        "secrets": {
            "gak": {"inline": GAK},
            "guek": {"inline": GUEK},
        },
    }
    return parse_config(
        {
            "transport": {"device": "/dev/null", "baudrate": 9600},
            "profiles": [
                {"name": "public", "role": "public"},
                secure,
            ],
        }
    )


class WorkflowTests(unittest.TestCase):
    def test_public_preflight_discovers_endpoint_identity_and_counter_candidates(self):
        config = multi_role_config().for_profile(multi_role_config().profiles[1])
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = PreflightSession
        PreflightSession.timeout_changes = []

        with (
            patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}),
            patch("dlms_enum.workflow.validate_serial_device"),
        ):
            result = run_public_preflight(config, object())

        self.assertEqual(result.transport["selected_baudrate"], 9600)
        self.assertEqual(result.meter_identity, "METER-1")
        self.assertEqual(result.association_view_objects, 2)
        self.assertEqual(len(result.counter_candidates), 1)
        self.assertEqual(result.counter_candidates[0].value, 1234)
        self.assertEqual(PreflightSession.timeout_changes, [1000])
        self.assertEqual(
            result.association["timeout_policy"]["enumeration_timeout_ms"], 1000
        )

    def test_role_selection_defaults_to_all(self):
        config = multi_role_config()
        console = Console(file=io.StringIO(), color_system=None)

        with patch("dlms_enum.tui.Prompt.ask", return_value="all"):
            selected = select_roles(config, console)

        self.assertEqual([item.role for item in selected], ["public", "client1"])

    def test_public_preflight_applies_timeout_breaker_to_candidate_reads(self):
        config = multi_role_config().for_profile(multi_role_config().profiles[0])
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = PreflightTimeoutSession
        PreflightTimeoutSession.timeout_changes = []

        with (
            patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}),
            patch("dlms_enum.workflow.validate_serial_device"),
        ):
            result = run_public_preflight(config, object())

        policy = result.association["timeout_policy"]
        self.assertEqual(policy["trips"], 1)
        self.assertEqual(policy["successful_health_checks"], 1)
        self.assertEqual(policy["recoveries_without_reconnect"], 1)
        self.assertFalse(policy["stopped"])

    def test_lls_only_preflight_uses_public_client_address(self):
        config = parse_config(
            {
                "transport": {"device": "/dev/null", "baudrate": 9600},
                "profiles": [
                    {
                        "name": "lls",
                        "client_address": 32,
                        "public_client_address": 16,
                        "authentication": {
                            "mechanism": "low",
                            "password": {"env": "TEST_DLMS_LLS_PASSWORD"},
                        },
                    }
                ],
            }
        )
        module = types.ModuleType("dlms_enum.gurux_adapter")
        module.GuruxSession = RecordingPreflightSession
        RecordingPreflightSession.client_addresses = []

        with (
            patch.dict(sys.modules, {"dlms_enum.gurux_adapter": module}),
            patch("dlms_enum.workflow.validate_serial_device"),
        ):
            run_public_preflight(config, object())

        self.assertEqual(RecordingPreflightSession.client_addresses, [16])

    def test_counter_confirmation_updates_only_runtime_secure_role(self):
        config = multi_role_config()
        profile = config.profiles[1]
        self.assertIsInstance(profile, SecureProfile)
        candidate = CounterCandidate(1, "0.0.43.1.7.255", 2, 900)
        preflight = PublicPreflight(
            transport={},
            association={},
            meter_identity="METER-1",
            association_view_objects=1,
            counter_candidates=(candidate,),
        )
        console = Console(file=io.StringIO(), color_system=None)

        with (
            patch("dlms_enum.tui.Prompt.ask", return_value="1") as prompt,
            patch("dlms_enum.tui.Confirm.ask", return_value=True) as confirm,
        ):
            chosen = verify_counter_source(
                select_counter_source(profile, candidate, meter_identity="METER-1"),
                preflight,
                console,
            )
        updated = select_counter_source(profile, chosen, meter_identity="METER-1")

        self.assertEqual(updated.invocation_counter.logical_name, candidate.logical_name)
        self.assertEqual(updated.invocation_counter.meter_identity, "METER-1")
        self.assertEqual(
            profile.invocation_counter.logical_name, "0.0.43.1.0.255"
        )
        rendered = console.file.getvalue()
        self.assertIn("Public-readable unsigned counter candidates", rendered)
        self.assertIn(candidate.logical_name, rendered)
        self.assertIn("Decoded current value: 900", rendered)
        self.assertNotIn("manual", rendered)
        prompt.assert_called_once()
        self.assertNotIn("choices", prompt.call_args.kwargs)
        confirm.assert_called_once()

    def test_counter_selection_accepts_unlisted_logical_name_after_confirmation(self):
        config = multi_role_config()
        profile = config.profiles[1]
        self.assertIsInstance(profile, SecureProfile)
        preflight = PublicPreflight(
            transport={},
            association={},
            meter_identity="METER-1",
            association_view_objects=0,
            counter_candidates=(),
        )
        console = Console(file=io.StringIO(), color_system=None)

        with (
            patch(
                "dlms_enum.tui.Prompt.ask",
                return_value="0.0.43.1.99.255",
            ),
            patch("dlms_enum.tui.Confirm.ask", return_value=True),
        ):
            chosen = verify_counter_source(profile, preflight, console)

        updated = select_counter_source(profile, chosen, meter_identity="METER-1")
        self.assertEqual(chosen.value, None)
        self.assertEqual(chosen.source, "operator_supplied")
        self.assertEqual(updated.invocation_counter.logical_name, "0.0.43.1.99.255")
        self.assertIn("No public-readable counter candidates", console.file.getvalue())
        self.assertIn("not read during preflight", console.file.getvalue())

    def test_counter_reuse_prompt_defaults_to_no(self):
        profile = multi_role_config().profiles[1]
        console = Console(file=io.StringIO(), color_system=None)

        with patch("dlms_enum.tui.Confirm.ask", return_value=False) as confirm:
            selected = choose_invocation_counter_reuse_test(profile, console)

        self.assertFalse(selected)
        self.assertFalse(confirm.call_args.kwargs["default"])
        self.assertIn("two protected GET requests", console.file.getvalue())

    def test_read_plan_accepts_only_a_total_get_limit(self):
        config = multi_role_config()
        preflight = PublicPreflight(
            transport={},
            association={"negotiated_conformance": ["multiple_references"]},
            meter_identity=None,
            association_view_objects=0,
            counter_candidates=(),
        )
        console = Console(file=io.StringIO(), color_system=None)

        with (
            patch("dlms_enum.tui.Confirm.ask", return_value=True),
            patch("dlms_enum.tui.IntPrompt.ask", return_value=5),
            patch("dlms_enum.tui.Prompt.ask", return_value="100"),
        ):
            planned = choose_read_plan(config, preflight, console)

        self.assertEqual(planned.scan.get_limit, 100)
        self.assertIsNone(planned.scan.object_limit)
        self.assertEqual(planned.scan.batch_size, 5)

    def test_preflight_endpoint_pins_all_selected_role_scans(self):
        config = multi_role_config()
        preflight = PublicPreflight(
            transport={
                "selected_baudrate": 19200,
                "selected_server_logical_address": 1,
                "selected_server_physical_address": 3,
                "server_address_size": 2,
            },
            association={},
            meter_identity=None,
            association_view_objects=0,
            counter_candidates=(),
        )

        effective = apply_preflight_endpoint(config, preflight)

        self.assertEqual(effective.transport.baudrate, 19200)
        self.assertTrue(
            all(profile.server_logical_address == 1 for profile in effective.profiles)
        )
        self.assertTrue(
            all(profile.server_physical_address == 3 for profile in effective.profiles)
        )
        self.assertTrue(
            all(profile.server_address_size == 2 for profile in effective.profiles)
        )


if __name__ == "__main__":
    unittest.main()
