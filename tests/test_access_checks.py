import io
import json
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from dlms_enum.access_policy import AccessPolicy, PolicyException, evaluate_profile
from dlms_enum.capability_comparison import build_role_matrix, compare_role_capabilities, render_comparison_markdown
from dlms_enum.config import ConfigError, parse_config
from dlms_enum.cross_role import GetBudget, execute_destination, parse_pairs, plan_checks, run_checks, render_checks
from dlms_enum.cli import _scan, build_parser
from dlms_enum.workflow import PublicPreflight


def config(secure=False):
    profiles = [{"name": "public", "role": "public"},
                {"name": "lls", "role": "reader", "client_address": 32,
                 "authentication": {"password": {"inline": "test-password"}}},
                {"name": "lls", "role": "operator", "client_address": 48,
                 "authentication": {"password": {"inline": "test-password"}}}]
    if secure:
        profiles.extend({"name": "hls_gmac_suite0", "role": role, "client_address": sap,
                         "client_system_title": "hex:434C49454E543031",
                         "secrets": {"gak": {"inline": "00" * 16}, "guek": {"inline": "11" * 16}}}
                        for role, sap in (("secure", 64), ("admin", 80)))
    return parse_config({"transport": {"device": "/dev/null", "baudrate": 9600, "session_guard_ms": 0},
                         "scan": {"common_catalogue": False}, "profiles": profiles})


def obj(name="1.0.99.1.0.255", class_id=7, read=True, write=False, version=0):
    return {"class_id": class_id, "logical_name": name, "object_version": version,
            "discovery_sources": ["association_view"],
            "attributes": [{"attribute_id": 2, "access_rights": {
                "read": read, "write": write, "raw": 1 if read else 0, "requirements": []},
                "outcome": "NOT_TESTED"}], "methods": []}


def snapshots(cfg):
    return {p.role: {"identity": {"role": p.role, "device": "/dev/null", "meter_identity": "METER-1",
                                 "client_address": p.client_address, "server_address": 1},
                     "source": "live", "objects": [obj(read=p.role != "public")]}
            for p in cfg.profiles}


class GXDLMSException(Exception):
    def __init__(self, code):
        super().__init__("sensitive-error-value")
        self.errorCode = code


class FakeSession:
    def __init__(self, authentication="none", client_address=16, script=()):
        self.authentication = authentication
        self.client_address = client_address
        self.script = iter(script)
        self.calls = []
        self.reconnections = 0
        self.counters = []

    def create_object(self, class_id, name):
        return types.SimpleNamespace(objectType=class_id, logicalName=name, version=0)

    def set_response_timeout(self, value):
        pass

    def read_attribute(self, target, attribute_id, attempt, **kwargs):
        self.calls.append((target.logicalName, attribute_id, kwargs["phase"]))
        self.counters.append(100 + len(self.calls))
        response = next(self.script, None)
        if isinstance(response, Exception):
            raise response
        return {"value": "do-not-retain-sensitive-value"}

    def details(self):
        return {"authentication": self.authentication, "client_address": self.client_address,
                "hls_validated": self.authentication == "high_gmac",
                "security": "authentication_encryption" if self.authentication == "high_gmac" else "none"}

    def reconnect(self):
        self.reconnections += 1
        return self.details()


class PolicyAndMatrixTests(unittest.TestCase):
    def test_three_roles_all_pairs_and_explicit_denial(self):
        cfg = config()
        views = snapshots(cfg)
        views["operator"]["objects"][0]["attributes"][0]["access_rights"]["requirements"] = ["encrypted_request"]
        matrix = build_role_matrix(views, [p.role for p in cfg.profiles])
        self.assertEqual(len(matrix["pairs"]), 3)
        get = next(r for r in matrix["capabilities"] if r["operation"] == "GET")
        self.assertEqual(get["roles"]["public"]["state"], "denied")
        self.assertEqual(get["roles"]["public"]["raw"], 0)
        self.assertEqual(matrix["pairs"][-1]["differences"][0]["classification"], "left_broader")

    def test_without_public_missing_view_versions_and_identity(self):
        views = snapshots(config())
        views.pop("public")
        views["operator"]["objects"][0]["object_version"] = 1
        matrix = build_role_matrix(views, ["reader", "operator", "missing"])
        self.assertEqual(matrix["pairs"][0]["differences"][0]["classification"], "version_mismatch")
        self.assertEqual(matrix["capabilities"][0]["roles"]["missing"]["state"], "view_unavailable")
        views["operator"]["identity"]["meter_identity"] = "OTHER"
        matrix = build_role_matrix(views, ["reader", "operator"])
        self.assertFalse(matrix["pairs"][0]["compatible_identity"])

    def test_confirmed_public_access_is_not_hidden_and_sap_mismatch_not_joined(self):
        views = snapshots(config())
        report = {"public_union_test": {"public_association": {"client_address": 16}, "results": [
            {"class_id": 7, "logical_name": "1.0.99.1.0.255", "attribute_id": 2,
             "attempt_count": 1, "outcome": "SUCCESS", "access_assessment": "UNEXPECTED_PUBLIC_ACCESS"}]}}
        comparison = compare_role_capabilities(views["public"], views["reader"], role_report=report)
        self.assertIn("UNEXPECTED_PUBLIC_ACCESS", render_comparison_markdown({"comparisons": [comparison]}))
        report["public_union_test"]["public_association"]["client_address"] = 17
        comparison = compare_role_capabilities(views["public"], views["reader"], role_report=report)
        self.assertIsNone(comparison["capabilities"][0]["public_get_verification"])

    def test_public_only_assessment_clock_read_write_and_equal_sensitive_access(self):
        objects = [obj(), obj("0.0.96.1.0.255", 1), obj("0.0.1.0.0.255", 8, write=True)]
        objects[0]["attributes"][0]["outcome"] = "SUCCESS"
        profile = {"name": "public", "association": {"authentication": "none"}, "objects": objects}
        assessment = evaluate_profile(profile, AccessPolicy())
        self.assertEqual(assessment["summary"], {"exposures": 2, "verified": 1, "exceptions": 0})
        self.assertEqual({(f["operation"], f["class_id"]) for f in assessment["findings"]}, {("GET", 7), ("SET", 8)})

    def test_low_privilege_lls_control_exception_retains_evidence(self):
        target = obj(class_id=70, write=True)
        target["methods"] = [{"method_id": 1, "access_rights": {"action": True}}]
        profile = {"name": "reader", "association": {"authentication": "low"}, "objects": [target]}
        policy = AccessPolicy(low_privilege_roles=("reader",), exceptions=(
            PolicyException("reader", 70, target["logical_name"], "ACTION", 1, "approved test function"),))
        report = evaluate_profile(profile, policy)
        self.assertEqual(report["summary"], {"exposures": 1, "verified": 0, "exceptions": 1})
        self.assertTrue(all(not f["verified"] for f in report["findings"]))

    def test_policy_config_validation(self):
        raw = {"transport": {"device": "/dev/null"}, "access_policy": {"low_privilege_roles": ["unknown"]}}
        with self.assertRaises(ConfigError):
            parse_config(raw)
        raw["access_policy"] = {"exceptions": [{"role": "public", "class_id": 7, "logical_name": "1.0.99.1.0.255",
                                                "operation": "GET", "member_id": 2, "reason": "approved"}]}
        self.assertEqual(parse_config(raw).access_policy.exceptions[0].reason, "approved")
        raw["access_policy"]["exceptions"][0]["reason"] = ""
        with self.assertRaises(ConfigError):
            parse_config(raw)


class CrossRoleTests(unittest.TestCase):
    def test_directed_pairs_all_profile_types_and_dedup(self):
        cfg = config(secure=True)
        views = snapshots(cfg)
        for role in ("reader", "secure"):
            views[role]["objects"][0]["attributes"][0]["access_rights"]["requirements"] = ["authenticated_request"]
        pairs = [("reader", "public"), ("secure", "public"), ("secure", "reader"), ("reader", "secure"), ("admin", "secure")]
        plan = plan_checks(cfg, views, pairs, 10)
        self.assertEqual(len(plan["requests"]), 3)
        public = next(r for r in plan["requests"] if r["probe_role"] == "public")
        self.assertEqual(public["source_roles"], ["reader", "secure"])
        with self.assertRaises(ValueError):
            parse_pairs(["public:public"], {"public"})

    def test_pair_limit_retains_untested_and_missing_view(self):
        cfg = config()
        views = snapshots(cfg)
        views["reader"]["objects"].append(obj("1.0.99.2.0.255"))
        views.pop("operator")
        plan = plan_checks(cfg, views, [("reader", "public"), ("operator", "public")], 1)
        pair = next(p for p in plan["pairs"] if p["source_role"] == "reader")
        self.assertEqual(len(plan["requests"]), 1)
        self.assertEqual(pair["candidates"][1]["reason"], "pair_limit")
        self.assertEqual(pair["candidates"][1]["outcome"], "NOT_TESTED")
        self.assertEqual(plan["pairs"][0]["reason"], "view_unavailable")

    def test_mismatched_role_sap_is_not_scheduled(self):
        cfg = config()
        views = snapshots(cfg)
        views["public"]["identity"]["client_address"] = 17
        plan = plan_checks(cfg, views, [("reader", "public")], 10)
        self.assertEqual(plan["requests"], [])
        self.assertEqual(plan["pairs"][0]["reason"], "role_identity_mismatch")

    def execute(self, script=(), budget_limit=20, count=1, role="public", threshold=2):
        cfg = config(secure=True)
        profile = next(p for p in cfg.profiles if p.role == role)
        runtime = replace(cfg.for_profile(profile), scan=replace(cfg.scan, timeout_breaker_threshold=threshold))
        views = snapshots(cfg)
        views[role]["objects"][0]["attributes"][0]["access_rights"]["read"] = False
        views["operator"]["objects"] = [obj(f"1.0.99.{i}.0.255") for i in range(1, count + 1)]
        requests = plan_checks(cfg, views, [("operator", role)], count)["requests"]
        auth = "none" if role == "public" else "high_gmac" if role in {"secure", "admin"} else "low"
        session = FakeSession(auth, profile.client_address, script)
        budget = GetBudget(budget_limit)
        result = execute_destination(session, session.details(),
            config=runtime, requests=requests, baseline={"class_id": 1, "logical_name": "0.0.42.0.0.255", "attribute_id": 1}, budget=budget)
        return result, session, budget

    def test_success_is_policy_violation_only_when_policy_prohibits(self):
        result, _, budget = self.execute()
        self.assertEqual(result["results"][0]["assessment"], "VERIFIED_POLICY_VIOLATION")
        self.assertEqual(budget.used, 2)
        self.assertNotIn("do-not-retain", json.dumps(result))
        for role in ("reader", "secure", "admin"):
            result, _, _ = self.execute(role=role)
            self.assertEqual(result["results"][0]["assessment"], "VERIFIED_ACCESS")

    def test_dlms_rejection_codes_not_exception_text(self):
        for code, expected in ((3, "access_denied"), (4, "object_unavailable"), (1, "other_dlms_error")):
            result, _, _ = self.execute(script=[None, GXDLMSException(code)])
            item = result["results"][0]
            self.assertEqual(item["rejection"], expected)
            self.assertEqual(item["attempt_count"], 1)
            self.assertNotIn("sensitive-error-value", json.dumps(result))

    def test_baseline_failure_sends_no_probes(self):
        result, session, budget = self.execute(script=[TimeoutError()], count=2)
        self.assertEqual(budget.used, 1)
        self.assertEqual(len(session.calls), 1)
        self.assertTrue(all(r["attempt_count"] == 0 for r in result["results"]))

    def test_budget_includes_retries_health_and_retains_unselected(self):
        result, session, budget = self.execute(script=[None, TimeoutError(), TimeoutError()], budget_limit=3, count=3)
        self.assertEqual(budget.used, 3)
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(result["results"][0]["assessment"], "INCONCLUSIVE")
        self.assertEqual(result["results"][1]["outcome"], "NOT_TESTED")
        self.assertEqual(session.reconnections, 0)

    def test_protected_recovery_and_second_trip_stops(self):
        result, session, budget = self.execute(
            script=[None, TimeoutError(), TimeoutError(), TimeoutError(), None, TimeoutError(), TimeoutError()],
            role="secure", count=3)
        self.assertEqual(session.reconnections, 1)
        self.assertEqual(budget.used, 7)
        self.assertEqual(len(set(session.counters)), len(session.calls))
        self.assertEqual(result["results"][-1]["reason"], "timeout_circuit_open")
        self.assertEqual(result["results"][-1]["attempt_count"], 0)

    def test_association_mismatch_is_not_probed(self):
        cfg = config().for_profile(config().profiles[0])
        session = FakeSession()
        budget = GetBudget(5)
        result = execute_destination(session, {"authentication": "low"}, config=cfg, requests=[], baseline={}, budget=budget)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(budget.used, 0)

    def test_unprotected_hls_association_is_not_used(self):
        cfg = config(secure=True)
        runtime = cfg.for_profile(next(p for p in cfg.profiles if p.role == "secure"))
        session = FakeSession("high_gmac", 64)
        details = {**session.details(), "security": "none"}
        budget = GetBudget(10)
        result = execute_destination(session, details, config=runtime, requests=[], baseline={}, budget=budget)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(budget.used, 0)

    def test_object_generation_failure_is_not_a_transmitted_probe(self):
        original = FakeSession.create_object
        def create(session, class_id, name):
            if class_id == 7:
                raise ValueError("unsupported class")
            return original(session, class_id, name)
        with patch.object(FakeSession, "create_object", create):
            result, session, budget = self.execute()
        self.assertEqual(result["results"][0]["outcome"], "ARGUMENT_GENERATION_FAILED")
        self.assertEqual(result["results"][0]["attempt_count"], 0)
        self.assertEqual(budget.used, 1)
        self.assertEqual(len(session.calls), 1)

    def test_shared_budget_across_destination_sessions(self):
        cfg = config()
        views = snapshots(cfg)
        views["reader"]["objects"][0]["attributes"][0]["access_rights"]["requirements"] = ["authenticated_request"]
        transport = {"selected_baudrate": 9600, "selected_server_logical_address": 0,
                     "selected_server_physical_address": 1, "server_address_size": 1}
        reports = {p.role: {"transport": transport} for p in cfg.profiles}
        sessions = []
        def fake_scan(runtime, logger, session_task):
            auth = "none" if runtime.profile.role == "public" else "low"
            session = FakeSession(auth, runtime.profile.client_address)
            sessions.append(session)
            return {"run": {"status": "completed"}, "access_check": session_task(session, session.details()), "errors": []}
        with tempfile.TemporaryDirectory() as directory, patch("dlms_enum.scanner.scan", side_effect=fake_scan):
            report = run_checks(cfg, views, reports, [("operator", "public"), ("operator", "reader")],
                pair_limit=3, transmission_limit=3, directory=Path(directory), authorization={"sha256": "test"})
        self.assertEqual(report["budget"]["get_attempts"], 3)
        self.assertEqual(sum(len(s.calls) for s in sessions), 3)
        self.assertEqual(report["requests"][1]["outcome"], "NOT_TESTED")
        self.assertIn("VERIFIED_POLICY_VIOLATION", render_checks(report))


class AccessCheckCliTests(unittest.TestCase):
    def test_invalid_pairs_and_authorization_fail_before_io(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / "auth.txt"
            auth.write_text("authorized lab meter")
            args = build_parser().parse_args(["access-check", "--config", "x.yaml", "--pair", "reader:missing", "--authorization", str(auth)])
            with patch("dlms_enum.cli.load_config", return_value=config()), patch("dlms_enum.cli.run_public_preflight") as preflight:
                with self.assertRaises(ValueError):
                    _scan(args, Console(file=io.StringIO()))
                preflight.assert_not_called()

    def test_full_public_lls_workflow_writes_active_and_passive_reports(self):
        cfg = replace(config(), profiles=config().profiles[:2])
        views = snapshots(cfg)
        transport = {"device": "/dev/null", "selected_baudrate": 9600, "selected_server_address": 1,
                     "selected_server_logical_address": 0, "selected_server_physical_address": 1,
                     "server_address_size": 1, "server_addressing_type": "1-byte addressing"}
        preflight = PublicPreflight(transport, {}, "METER-1", 1, ())
        def inventory(runtime, *args, **kwargs):
            p = runtime.profile
            return {"schema_version": 1, "run": {"status": "completed"}, "effective_configuration": runtime.redacted_dict(),
                    "transport": transport, "profiles": [{"name": p.role, "objects": views[p.role]["objects"],
                    "association": {"authentication": "none" if p.role == "public" else "low", "client_address": p.client_address},
                    "summary": {}}], "errors": []}
        def active(runtime, logger, session_task):
            self.assertEqual(runtime.profile.role, "public")
            session = FakeSession()
            return {"run": {"status": "completed"}, "access_check": session_task(session, session.details()), "errors": []}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth = root / "auth.txt"
            auth.write_text("authorized test fixture")
            args = build_parser().parse_args(["access-check", "--config", "x.yaml", "--pair", "reader:public", "--authorization", str(auth)])
            with patch("dlms_enum.cli.load_config", return_value=cfg), patch("dlms_enum.cli._run_directory", return_value=root), \
                 patch("dlms_enum.cli.run_public_preflight", return_value=preflight), patch("dlms_enum.cli.scan", side_effect=inventory), \
                 patch("dlms_enum.scanner.scan", side_effect=active), patch("dlms_enum.cli.ScanUI.summary"):
                status = _scan(args, Console(file=io.StringIO()))
            self.assertEqual(status, 0)
            report = json.loads((root / "access-check.json").read_text())
            self.assertEqual(report["requests"][0]["assessment"], "VERIFIED_POLICY_VIOLATION")
            self.assertTrue((root / "capability-comparison.json").exists())
            self.assertEqual(len(report["authorization"]["sha256"]), 64)
            self.assertIn("reader", (root / "access-check.md").read_text())


if __name__ == "__main__":
    unittest.main()
