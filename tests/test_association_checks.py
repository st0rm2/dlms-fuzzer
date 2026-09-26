import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_access_checks import config, snapshots, obj, FakeSession, GXDLMSException
from dlms_enum.association_checks import parse_instances, hidden_requests, association_snapshot, control_findings
from dlms_enum.cross_role import execute_destination, GetBudget, run_checks, render_checks
from dlms_enum.capability_comparison import build_role_matrix, render_role_matrix
from dlms_enum.cli import build_parser


def raw_entry(class_id, name, version=0, mode=1):
    return [class_id, version, bytes(int(x) for x in name.split('.')), [[[2, mode, None]], [[1, 1]]]]


class HiddenSession(FakeSession):
    def read_association_objects(self, name, attempt):
        self.calls.append((name, 2, 'hidden_list'))
        return [raw_entry(15, name, 3), raw_entry(70, '0.0.96.3.10.255', mode=5)]


class AssociationChecksTests(unittest.TestCase):
    def test_range_validation_and_advertised_exclusion(self):
        for value in ('1', '-1:2', '4:2', '0:256', 'a:b', '1:2:3'):
            with self.assertRaises(ValueError):
                parse_instances(value)
        self.assertEqual(len(parse_instances('0:255')), 256)
        requests = hidden_requests('public', {'objects': [obj('0.0.40.0.2.255', 15)]}, parse_instances('1:3'))
        self.assertEqual([r['logical_name'] for r in requests],
                         ['0.0.40.0.1.255'] * 2 + ['0.0.40.0.3.255'] * 2)

    def execute(self, session, limit=10):
        cfg = config().for_profile(config().profiles[0])
        requests = hidden_requests('public', {'objects': []}, range(1, 2))
        budget = GetBudget(limit)
        result = execute_destination(session, session.details(), config=cfg, requests=requests,
            baseline={'class_id': 15, 'logical_name': '0.0.40.0.0.255', 'attribute_id': 1}, budget=budget)
        return result, budget

    def test_hidden_list_and_presence_share_budget(self):
        result, budget = self.execute(HiddenSession())
        self.assertEqual(budget.used, 3)
        self.assertEqual(result['results'][0]['assessment'], 'HIDDEN_ASSOCIATION_PRESENT')
        self.assertEqual(result['results'][1]['assessment'], 'HIDDEN_ASSOCIATION_LIST_READABLE')
        view = result['results'][1]['discovered_view']
        self.assertTrue(view['rights_encoding_known'])
        self.assertEqual(view['objects'][1]['attributes'][0]['access_rights']['requirements'], ['authenticated_request'])
        result, budget = self.execute(HiddenSession(), 2)
        self.assertEqual(result['results'][1]['outcome'], 'NOT_TESTED')
        self.assertEqual(budget.used, 2)

    def test_denied_presence_does_not_read_list(self):
        session = HiddenSession(script=[None, GXDLMSException(3)])
        result, budget = self.execute(session)
        self.assertEqual(budget.used, 2)
        self.assertEqual(result['results'][0]['assessment'], 'REJECTED')
        self.assertEqual(result['results'][1]['reason'], 'presence_not_confirmed')

    def test_unknown_encoding_and_malformed_list(self):
        view = association_snapshot([raw_entry(70, '0.0.96.3.10.255')], '0.0.40.0.1.255', {})
        self.assertFalse(view['rights_encoding_known'])
        self.assertEqual(view['objects'][0]['attributes'], [])
        self.assertTrue(view['objects'][0]['uninterpreted_rights'])
        for value in ([[]], [raw_entry(70, '0.0.96.3.10.255')] * 2):
            with self.assertRaises(ValueError):
                association_snapshot(value, '0.0.40.0.1.255', {})

    def test_control_instances_compare_permissions_requirements_and_versions(self):
        left, right = obj('0.0.96.3.10.255', 70), obj('0.0.96.3.11.255', 70)
        snapshot = {'objects': [left, right]}
        self.assertEqual(control_findings(snapshot, 'public'), [])
        right['attributes'][0]['access_rights']['write'] = True
        findings = control_findings(snapshot, 'public')
        self.assertEqual(findings[0]['differences'][0]['operation'], 'SET')
        self.assertEqual(findings[0]['differences'][0]['classification'], 'inconsistent_rights')
        matrix = build_role_matrix({'public': snapshot}, ['public'])
        self.assertIn('A5', render_role_matrix(matrix))
        right['object_version'] = 1
        self.assertTrue(all(d['classification'] == 'version_mismatch' for d in control_findings(snapshot, 'public')[0]['differences']))

    def test_hidden_and_control_workflow_artifacts(self):
        cfg = config()
        views = snapshots(cfg)
        views['public']['objects'] += [obj('0.0.96.3.10.255', 70), obj('0.0.96.3.11.255', 70, write=True)]
        transport = {'selected_baudrate': 9600, 'selected_server_logical_address': 0,
                     'selected_server_physical_address': 1, 'server_address_size': 1}
        def scan(runtime, logger, session_task):
            session = HiddenSession()
            return {'run': {'status': 'completed'}, 'errors': [],
                    'access_check': session_task(session, session.details())}
        with tempfile.TemporaryDirectory() as directory, patch('dlms_enum.scanner.scan', side_effect=scan):
            report = run_checks(cfg, views, {'public': {'transport': transport}}, [], pair_limit=2,
                transmission_limit=10, directory=Path(directory), authorization={}, hidden_roles=['public'],
                control_roles=['public'], instances=range(1, 2))
            self.assertTrue((Path(directory) / 'access-check-1.json').exists())
        self.assertEqual(report['budget']['get_attempts'], 5)
        self.assertEqual(len(report['hidden_view_comparisons']), 1)
        self.assertEqual(report['control_roles'][0]['status'], 'completed')
        self.assertIn('HIDDEN_ASSOCIATION_LIST_READABLE', render_checks(report))
        self.assertIn('Control-instance GET', render_checks(report))
        self.assertEqual(len(views['public']['objects']), 3)  # original view not overwritten

    def test_missing_view_retained_and_cli_allows_hidden_only(self):
        args = build_parser().parse_args(['access-check', '--config', 'lab.yaml', '--authorization', 'auth.txt',
                                          '--hidden-associations', 'public'])
        self.assertEqual(args.pair, [])
        with tempfile.TemporaryDirectory() as directory:
            report = run_checks(config(), {}, {}, [], pair_limit=2, transmission_limit=2,
                                directory=Path(directory), authorization={}, hidden_roles=['public'])
        self.assertEqual(report['hidden_roles'][0]['reason'], 'view_unavailable')
        self.assertEqual(report['budget']['get_attempts'], 0)

    def test_adapter_reads_requested_list_without_replacing_session_objects(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from dlms_enum.gurux_adapter import GuruxSession
        session = object.__new__(GuruxSession)
        original = [object()]
        session.client = SimpleNamespace(settings=SimpleNamespace(objects=original), read=Mock(return_value=b"request"))
        session.profile_name = "public"
        session.create_object = Mock(return_value=object())
        entries = [raw_entry(15, "0.0.40.0.2.255", 3)]
        def blocks(request, reply, **kwargs):
            self.assertEqual(kwargs["object_context"]["logical_name"], "0.0.40.0.2.255")
            reply.value = entries
        session._read_blocks = blocks
        self.assertEqual(session.read_association_objects("0.0.40.0.2.255", 1), entries)
        self.assertIs(session.client.settings.objects, original)
        session.client.read.assert_called_once_with(session.create_object.return_value, 2)

    def test_legacy_rights_encoding_and_method_requirements(self):
        entry = raw_entry(15, "0.0.40.0.1.255", version=2, mode=4)
        entry[3][1][0][1] = 2
        view = association_snapshot([entry], "0.0.40.0.1.255", {})
        rights = view["objects"][0]["attributes"][0]["access_rights"]
        self.assertTrue(rights["read"])
        self.assertFalse(rights["write"])
        self.assertEqual(rights["requirements"], ["authenticated_request"])
        self.assertEqual(view["objects"][0]["methods"][0]["access_rights"]["requirements"], ["authenticated_request"])

    def test_malformed_list_is_inconclusive_and_budgeted(self):
        class MalformedSession(HiddenSession):
            def read_association_objects(self, name, attempt):
                return [[]]
        result, budget = self.execute(MalformedSession(), 3)
        self.assertEqual(budget.used, 3)
        self.assertEqual(result["results"][1]["assessment"], "INCONCLUSIVE")
        self.assertNotIn("discovered_view", result["results"][1])
