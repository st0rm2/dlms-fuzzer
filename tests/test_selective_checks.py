import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from test_access_checks import config, snapshots, obj, FakeSession, GXDLMSException
from dlms_enum.selective_checks import parse_range, validate_options, candidates, clock_descriptor, execute, run_selective_checks
from dlms_enum.cross_role import GetBudget, run_checks, render_checks
from dlms_enum.gurux_adapter import GuruxSession

CLOCK = [8, bytes([0, 0, 1, 0, 0, 255]), 2, 0]


class ProfileSession(FakeSession):
    def __init__(self, responses):
        super().__init__()
        self.responses = iter(responses)

    def prepare_profile_read(self, target, attribute, selector):
        return b'request'

    def send_profile_read(self, packets, target, attribute, selector):
        self.calls.append((int(target.objectType), attribute, selector))
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result


class SelectiveChecksTests(unittest.TestCase):
    def run_probe(self, responses, bounds=None, budget_limit=20, views=None):
        cfg = config().for_profile(config().profiles[0])
        targets = candidates(views or {'objects': [obj(read=False)]}, 5)
        session = ProfileSession(responses)
        budget = GetBudget(budget_limit)
        result = execute(session, session.details(), cfg, targets, budget, bounds, {})
        return result, session, budget

    def test_selection_and_input_validation(self):
        snapshot = {'objects': [obj(read=True), obj('1.0.99.2.0.255', read=False), obj('1.0.99.3.0.255', read=False)]}
        selected = candidates(snapshot, 1)
        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[1]['reason'], 'target_limit')
        snapshot['objects'][0]['attributes'][0]['access_rights']['requirements'] = ['authenticated_request']
        self.assertEqual(len(candidates(snapshot, 5)), 3)
        for start, end in [('2026-09-26T10:00:00', '2026-09-26T10:01:00'), ('bad', 'bad'),
                           ('2026-09-26T10:00:00Z', None), ('2026-09-26T10:00:00Z', '2026-09-26T12:00:00Z'),
                           ('2026-09-26T10:00:00Z', '2026-09-26T09:00:00Z')]:
            with self.assertRaises(ValueError):
                parse_range(start, end)
        for roles, limit in [(['missing'], 5), (['public', 'public'], 5), ([], 0), ([], 33)]:
            with self.assertRaises(ValueError):
                validate_options(config(), roles, limit)

    def test_data_after_denial_has_no_values(self):
        result, session, budget = self.run_probe([None, GXDLMSException(3), [['private-reading']]])
        self.assertEqual(result['targets'][0]['status'], 'DATA_AFTER_NORMAL_DENIAL')
        self.assertEqual(budget.used, 3)
        self.assertEqual(session.calls[-1][2], {'kind': 'entry'})
        self.assertNotIn('private-reading', json.dumps(result))
        self.assertEqual(result['targets'][0]['reads'][1]['row_count'], 1)

    def test_empty_response_and_rejection_are_distinct(self):
        for response, expected in [([], 'EMPTY_RESPONSE'), ([[]], 'EMPTY_RESPONSE'),
                                   (GXDLMSException(3), 'SELECTIVE_READS_REJECTED')]:
            result, _, _ = self.run_probe([None, GXDLMSException(3), response])
            self.assertEqual(result['targets'][0]['status'], expected)

    def test_normal_success_or_other_error_never_enables_selectors(self):
        for response, expected in [([['private']], 'NORMAL_READ_ALLOWED'), (GXDLMSException(4), 'INCONCLUSIVE'),
                                   (TimeoutError(), 'INCONCLUSIVE')]:
            result, session, budget = self.run_probe([None, response])
            self.assertEqual(result['targets'][0]['status'], expected)
            self.assertEqual(budget.used, 2)
            self.assertEqual(len(session.calls), 2)

    def test_valid_range_uses_actual_clock_descriptor(self):
        bounds = parse_range('2026-09-26T10:00:00Z', '2026-09-26T10:05:00Z')
        result, session, budget = self.run_probe([None, GXDLMSException(3), [], [CLOCK], CLOCK, [[42]]], bounds)
        self.assertEqual(budget.used, 6)
        self.assertEqual(session.calls[-1][2]['clock_logical_name'], '0.0.1.0.0.255')
        self.assertEqual(session.calls[-1][2]['start'], bounds[0])
        self.assertEqual(result['targets'][0]['reads'][-1]['assessment'], 'DATA_AFTER_NORMAL_DENIAL')

    def test_invalid_metadata_does_not_guess_range(self):
        self.assertIsNone(clock_descriptor([CLOCK], [8, CLOCK[1], 3, 0]))
        self.assertIsNone(clock_descriptor([], CLOCK))
        bounds = parse_range('2026-09-26T10:00:00Z', '2026-09-26T10:05:00Z')
        result, session, budget = self.run_probe([None, GXDLMSException(3), [], [], CLOCK], bounds)
        self.assertEqual(result['targets'][0]['reads'][-1]['reason'], 'valid_clock_metadata_unavailable')
        self.assertEqual(result['targets'][0]['status'], 'INCONCLUSIVE')
        self.assertEqual(budget.used, 5)

    def test_budget_and_inconclusive_exchange_stop_session(self):
        result, session, budget = self.run_probe([None, GXDLMSException(3)], budget_limit=2)
        self.assertEqual(result['targets'][0]['status'], 'INCONCLUSIVE')
        self.assertEqual(budget.used, 2)
        views = {'objects': [obj(read=False), obj('1.0.99.2.0.255', read=False)]}
        result, session, budget = self.run_probe([None, GXDLMSException(3), TimeoutError()], views=views)
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(result['targets'][1]['reason'], 'inconclusive_exchange')
        self.assertEqual(session.reconnections, 0)

    def test_malformed_buffer_and_generation_failure(self):
        result, _, _ = self.run_probe([None, GXDLMSException(3), {'not': 'array'}])
        self.assertEqual(result['targets'][0]['status'], 'INCONCLUSIVE')
        with patch.object(ProfileSession, 'prepare_profile_read', side_effect=ValueError()):
            result, _, budget = self.run_probe([])
        self.assertEqual(budget.used, 0)
        self.assertEqual(result['status'], 'inconclusive')

    def test_adapter_entry_is_exactly_one_row_and_range_sets_sort_clock(self):
        session = object.__new__(GuruxSession)
        session.client = types.SimpleNamespace(readRowsByEntry=Mock(return_value=b'entry'), readRowsByRange=Mock(return_value=b'range'))
        session.create_object = Mock(return_value='clock')
        target = types.SimpleNamespace()
        session.prepare_profile_read(target, 2, {'kind': 'entry'})
        session.client.readRowsByEntry.assert_called_once_with(target, 1, 1)
        bounds = parse_range('2026-09-26T10:00:00Z', '2026-09-26T10:05:00Z')
        session.prepare_profile_read(target, 2, {'kind': 'range', 'clock_logical_name': '0.0.1.0.0.255', 'start': bounds[0], 'end': bounds[1]})
        self.assertEqual(target.sortObject, 'clock')
        session.client.readRowsByRange.assert_called_once_with(target, *bounds)

    def test_block_and_byte_limits_stop_continuations(self):
        from gurux_dlms import GXReplyData
        session = object.__new__(GuruxSession)
        session.client = types.SimpleNamespace(receiverReady=Mock(return_value=b'next'))
        for oversize, expected in [(False, 5), (True, 1)]:
            reply = GXReplyData()
            calls = []
            def exchange(packet, reply, **kwargs):
                calls.append(packet)
                reply.moreData = 1
                if oversize:
                    reply.data.set(bytes(65537))
            session._exchange_packet = exchange
            with self.assertRaises(ValueError):
                session._read_blocks(b'get', reply, phase='selective_access', purpose='test', operation='GET', attempt=1)
            self.assertEqual(len(calls), expected)

    def test_aggregate_workflow_and_missing_view(self):
        cfg = config()
        views = snapshots(cfg)
        transport = {'selected_baudrate': 9600, 'selected_server_logical_address': 0,
                     'selected_server_physical_address': 1, 'server_address_size': 1}
        def scan(runtime, logger, session_task):
            session = ProfileSession([None, GXDLMSException(3), [['secret']]])
            return {'run': {'status': 'completed'}, 'errors': [], 'access_check': session_task(session, session.details())}
        with tempfile.TemporaryDirectory() as directory, patch('dlms_enum.scanner.scan', side_effect=scan):
            report = run_checks(cfg, views, {'public': {'transport': transport}}, [], pair_limit=2,
                transmission_limit=5, directory=Path(directory), authorization={}, selective_roles=['public'])
            self.assertTrue((Path(directory) / 'selective-access-1.json').exists())
            self.assertNotIn('secret', (Path(directory) / 'selective-access-1.json').read_text())
        self.assertEqual(report['budget']['get_attempts'], 3)
        self.assertIn('DATA_AFTER_NORMAL_DENIAL', render_checks(report))
        with tempfile.TemporaryDirectory() as directory, patch('dlms_enum.scanner.scan') as scan:
            result = run_selective_checks(cfg, {}, {}, ['public'], 5, None, GetBudget(5), Path(directory))
        scan.assert_not_called()
        self.assertEqual(result[0]['reason'], 'view_unavailable')

    def test_buffer_traffic_omits_raw_and_all_decoded_response_projections(self):
        import contextlib
        from gurux_dlms import GXReplyData
        session = object.__new__(GuruxSession)
        session.config = config().for_profile(config().profiles[0])
        session.profile_name = 'public'
        session._endpoint_context = lambda: {}
        session._before_transmit = lambda *a, **kw: {}
        session._after_transmit = lambda *a, **kw: None
        session._after_receive = lambda *a, **kw: {'decrypted': 'private-reading'}
        session._frame_xml = lambda frame: {'xml': 'private-reading' if frame == b'private-reading' else 'request'}
        session.traffic = types.SimpleNamespace(log=Mock())
        def get_data(frame, reply, notification):
            if frame.size == 0:
                return False
            reply.value = [['private-reading']]
            return True
        session.client = types.SimpleNamespace(getData=get_data)
        def receive(parameters):
            parameters.reply = b'private-reading'
            return True
        session.media = types.SimpleNamespace(getSynchronous=contextlib.nullcontext, send=lambda packet: None, receive=receive)
        session._exchange_packet(b'get', GXReplyData(), phase='selective_access', purpose='test', operation='GET', attempt=1,
                                 object_context={'class_id': 7, 'attribute_id': 2})
        logged = session.traffic.log.call_args.kwargs
        self.assertEqual(logged['rx_frames'], [])
        self.assertEqual(logged['rx_decoded'], {'buffer_response_omitted': True})
        self.assertNotIn('private-reading', str(logged))

    def test_unknown_rights_not_selected_and_wrong_association_not_used(self):
        view = {'objects': [obj(read=False)]}
        view['objects'][0]['attributes'][0]['access_rights'] = {}
        self.assertEqual(candidates(view, 5), [])
        cfg = config().for_profile(config().profiles[0])
        session = ProfileSession([])
        budget = GetBudget(10)
        result = execute(session, {**session.details(), 'client_address': 32}, cfg,
                         candidates({'objects': [obj(read=False)]}, 5), budget, None, {})
        self.assertEqual(result['status'], 'inconclusive')
        self.assertEqual(budget.used, 0)

    def test_cli_invalid_range_fails_before_io(self):
        import io
        from rich.console import Console
        from dlms_enum.cli import build_parser, _scan
        with tempfile.TemporaryDirectory() as directory:
            auth = Path(directory) / 'auth.txt'
            auth.write_text('authorized target')
            args = build_parser().parse_args(['access-check', '--config', 'lab.yaml', '--authorization', str(auth),
                                              '--selective-access', 'public', '--selective-range-start', 'bad'])
            with patch('dlms_enum.cli.load_config', return_value=config()), patch('dlms_enum.cli.run_public_preflight') as preflight:
                with self.assertRaises(ValueError):
                    _scan(args, Console(file=io.StringIO()))
                preflight.assert_not_called()
