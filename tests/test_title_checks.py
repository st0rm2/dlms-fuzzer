import io
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from rich.console import Console
from test_access_checks import config, snapshots, FakeSession
from test_association_checks import raw_entry
from dlms_enum.cli import build_parser, _scan
from dlms_enum.cross_role import GetBudget, run_checks, render_checks
from dlms_enum.title_checks import parse_titles, read_view, run_title_checks
from dlms_enum.counter_state import counter_identity, acquire_counter_lease

VARIANT = bytes.fromhex('434C49454E543032')


class TitleSession(FakeSession):
    def __init__(self, profile, changed=False):
        super().__init__('high_gmac', profile.client_address)
        self.profile = profile
        self.changed = changed

    def details(self):
        return {**super().details(), 'security_suite': 0, 'server_system_title': '4D45544552303031',
                'client_system_title': self.profile.client_system_title.hex().upper()}

    def read_association_objects(self, name, attempt):
        self.calls.append((name, 2, 'title_view'))
        return [raw_entry(15, name, version=3),
                raw_entry(70, '0.0.96.3.10.255', mode=3 if self.changed else 1)]


class TitleChecksTests(unittest.TestCase):
    def setUp(self):
        self.config = config(secure=True)
        self.profile = next(p for p in self.config.profiles if p.role == 'secure')
        self.runtime = self.config.for_profile(self.profile)
        self.views = snapshots(self.config)
        self.transport = {'selected_baudrate': 9600, 'selected_server_logical_address': 0,
                          'selected_server_physical_address': 1, 'server_address_size': 1}
        self.reports = {'secure': {'transport': self.transport}}

    def test_validation(self):
        self.assertEqual(parse_titles(['secure:' + VARIANT.hex()], self.config, 4), {'secure': [VARIANT]})
        for values, limit in [(['public:' + VARIANT.hex()], 4), (['reader:' + VARIANT.hex()], 4),
                              (['missing:' + VARIANT.hex()], 4), (['secure:00'], 4),
                              (['secure:' + self.profile.client_system_title.hex()], 4),
                              (['secure:' + VARIANT.hex()] * 2, 4),
                              (['secure:' + VARIANT.hex()], 0), ([], 33),
                              (['secure:' + VARIANT.hex(), 'secure:434C49454E543033'], 1)]:
            with self.assertRaises(ValueError):
                parse_titles(values, self.config, limit)
        unsafe = replace(self.profile, invocation_counter=replace(self.profile.invocation_counter, unsafe_override=10))
        with self.assertRaises(ValueError):
            parse_titles(['secure:' + VARIANT.hex()], self.config.for_profile(unsafe), 4)

    def test_cli_validation_precedes_io(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / 'authorization.txt'
            auth.write_text('authorized test target')
            args = build_parser().parse_args(['access-check', '--config', 'test.yaml', '--authorization', str(auth),
                                              '--system-title', 'public:' + VARIANT.hex()])
            with patch('dlms_enum.cli.load_config', return_value=self.config), \
                 patch('dlms_enum.cli.run_public_preflight') as preflight:
                with self.assertRaises(ValueError):
                    _scan(args, Console(file=io.StringIO()))
                preflight.assert_not_called()

    def test_negotiated_properties_and_server_identity_checked_before_get(self):
        for properties in ({'client_system_title': VARIANT.hex().upper()}, {'security_suite': 1},
                           {'hls_validated': False}, {'client_address': 16}, {'security': 'none'}):
            session = TitleSession(self.profile)
            budget = GetBudget(10)
            result = read_view(session, {**session.details(), **properties}, self.runtime, budget)
            self.assertEqual(result['reason'], 'association_properties_mismatch')
            self.assertEqual(budget.used, 0)
        session = TitleSession(self.profile)
        result = read_view(session, session.details(), self.runtime, GetBudget(10), 'OTHER')
        self.assertEqual(result['reason'], 'server_identity_mismatch')

    def test_get_budget_and_timeout_cap(self):
        session = TitleSession(self.profile)
        result = read_view(session, session.details(), self.runtime, GetBudget(1))
        self.assertEqual(result['reason'], 'transmission_limit')
        self.assertEqual(len(session.calls), 1)
        class TimeoutSession(TitleSession):
            def read_attribute(self, *args, **kwargs):
                raise TimeoutError()
        session = TimeoutSession(self.profile)
        budget = GetBudget(10)
        result = read_view(session, session.details(), self.runtime, budget)
        self.assertEqual(result['reason'], 'baseline_get_failed')
        self.assertLessEqual(budget.used, self.config.scan.timeout_breaker_threshold)
        self.assertEqual(session.reconnections, 0)

    def run_variants(self, *, changed=False, failure=None, limit=20):
        sessions = []
        def scan(runtime, logger, session_task):
            self.assertEqual(runtime.profile.client_address, self.profile.client_address)
            self.assertIs(runtime.profile.secrets, self.profile.secrets)
            self.assertEqual(runtime.profile.invocation_counter, self.profile.invocation_counter)
            self.assertEqual(runtime.transport.baudrate, 9600)
            sessions.append(runtime.profile.client_system_title)
            if failure and len(sessions) == failure[0]:
                return {'run': {'status': failure[1]}, 'errors': [], **failure[2]}
            session = TitleSession(runtime.profile, changed and len(sessions) > 1)
            return {'run': {'status': 'completed'}, 'errors': [],
                    'access_check': session_task(session, session.details())}
        with tempfile.TemporaryDirectory() as directory, patch('dlms_enum.scanner.scan', side_effect=scan):
            report = run_checks(self.config, self.views, self.reports, [], pair_limit=2,
                transmission_limit=limit, directory=Path(directory), authorization={}, title_variants={'secure': [VARIANT]})
            if sessions:
                self.assertTrue((Path(directory) / 'system-title-1-0.json').exists())
        return report, sessions

    def test_changed_view_and_per_title_reports(self):
        report, sessions = self.run_variants(changed=True)
        result = report['system_title_checks'][0]
        self.assertEqual(result['baseline']['status'], 'VIEW_READ')
        self.assertEqual(result['variants'][0]['status'], 'VIEW_CHANGED')
        self.assertEqual(result['variants'][0]['assessment'], 'review_required')
        self.assertTrue(result['variants'][0]['changes']['changed'])
        self.assertEqual(sessions, [self.profile.client_system_title, VARIANT])
        self.assertEqual(report['budget']['get_attempts'], 4)
        self.assertIn('VIEW_CHANGED', render_checks(report))

    def test_unchanged_view(self):
        report, _ = self.run_variants()
        self.assertEqual(report['system_title_checks'][0]['variants'][0]['status'], 'VIEW_UNCHANGED')

    def test_baseline_failure_blocks_variants(self):
        report, sessions = self.run_variants(failure=(1, 'failed', {}))
        self.assertEqual(len(sessions), 1)
        self.assertEqual(report['system_title_checks'][0]['variants'][0]['reason'], 'baseline_failed')

    def test_explicit_association_rejection_and_transport_failure_are_distinct(self):
        for evidence, expected in [({'secure_association_failure': {'association_result': 1, 'diagnostic': 13}}, 'ASSOCIATION_REJECTED'),
                                   ({}, 'INCONCLUSIVE')]:
            report, _ = self.run_variants(failure=(2, 'failed', evidence))
            self.assertEqual(report['system_title_checks'][0]['variants'][0]['status'], expected)

    def test_interruption_and_exhausted_budget_stop_sessions(self):
        report, sessions = self.run_variants(failure=(1, 'interrupted', {}))
        self.assertEqual(len(sessions), 1)
        self.assertEqual(report['system_title_checks'][0]['variants'][0]['reason'], 'interrupted')
        report, sessions = self.run_variants(limit=2)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(report['system_title_checks'][0]['variants'][0]['reason'], 'transmission_limit')

    def test_missing_view_skips_without_io(self):
        with tempfile.TemporaryDirectory() as directory, patch('dlms_enum.scanner.scan') as scan:
            results = run_title_checks(self.config, {}, {}, {'secure': [VARIANT]}, GetBudget(10), Path(directory))
        scan.assert_not_called()
        self.assertEqual(results[0]['baseline']['reason'], 'view_unavailable')

    def test_counter_leases_are_distinct_and_persistent_per_title(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'counters.json'
            identities = [counter_identity(meter_identity='METER-1', client_system_title=title,
                          client_address=64, server_address=1) for title in (self.profile.client_system_title, VARIANT)]
            keys = []
            for identity, next_value in zip(identities, (100, 200)):
                with acquire_counter_lease(path, identity, meter_reported_counter=10, unsafe_override=None) as lease:
                    keys.append(lease.identity_key)
                    lease.persist_next(next_value)
            self.assertNotEqual(keys[0], keys[1])
            for identity, expected in zip(identities, (100, 200)):
                with acquire_counter_lease(path, identity, meter_reported_counter=10, unsafe_override=None) as lease:
                    self.assertEqual(lease.next_counter, expected)

    def test_meter_identity_and_endpoint_mismatch_prevent_gets(self):
        session = TitleSession(self.profile)
        for details, reason in [({'invocation_counter_bootstrap': {'meter_identity': 'OTHER'}}, 'meter_identity_mismatch'),
                                ({'server_address': 99}, 'server_endpoint_mismatch')]:
            budget = GetBudget(10)
            result = read_view(session, {**session.details(), **details}, self.runtime, budget,
                               expected_identity={'meter_identity': 'METER-1', 'server_address': 1})
            self.assertEqual(result['reason'], reason)
            self.assertEqual(budget.used, 0)

    def test_object_creation_failure_consumes_no_get_budget(self):
        session = TitleSession(self.profile)
        with patch.object(session, 'create_object', side_effect=ValueError('unsupported')):
            budget = GetBudget(10)
            result = read_view(session, session.details(), self.runtime, budget)
        self.assertEqual(result['reason'], 'object_creation_failed')
        self.assertEqual(budget.used, 0)
