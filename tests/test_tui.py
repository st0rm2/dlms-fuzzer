import io
import unittest

from rich.console import Console

from dlms_enum.reporter import summary_lines
from dlms_enum.tui import ScanUI


class ScanUITests(unittest.TestCase):
    def test_progress_refreshes_independently_once_per_second(self):
        ui = ScanUI(Console(file=io.StringIO(), color_system=None, width=200))

        self.assertTrue(ui._progress.live.auto_refresh)
        self.assertEqual(ui._progress.live.refresh_per_second, 1)

    def test_error_progress_event_is_rendered_as_an_error(self):
        output = io.StringIO()
        ui = ScanUI(Console(file=output, color_system=None, width=200))

        ui.progress(
            {
                "phase": "scan_error",
                "level": "error",
                "message": "Permission denied for serial device /dev/ttyUSB0",
            }
        )

        self.assertIn(
            "Error: Permission denied for serial device /dev/ttyUSB0",
            output.getvalue(),
        )

    def test_summary_labels_discovered_server_addressing_type(self):
        report = {
            "run": {"id": "test", "status": "completed"},
            "transport": {
                "selected_baudrate": 9600,
                "selected_server_address": 1,
                "server_addressing_type": "1-byte addressing",
            },
            "profiles": [],
            "errors": [],
        }

        lines = summary_lines(report)

        self.assertIn("HDLC server address: 1", lines)
        self.assertIn("Server Addressing Type: 1-byte addressing", lines)

    def test_get_events_render_one_rich_progress_task_with_current_action(self):
        output = io.StringIO()
        ui = ScanUI(Console(file=output, color_system=None, width=180))

        ui.progress({"phase": "get_plan", "total": 2, "message": "Scanning 2 readable attributes"})
        ui.progress(
            {
                "phase": "get_scan",
                "logical_name": "1.0.1.8.0.255",
                "class_id": 3,
                "attribute_id": 2,
                "attempt": 1,
            }
        )
        ui.progress({"phase": "get_complete"})
        ui.close()

        rendered = output.getvalue()
        self.assertIn("GET 1.0.1.8.0.255  class 3  attribute 2  attempt 1", rendered)
        self.assertIn("1/2", rendered)


if __name__ == "__main__":
    unittest.main()
