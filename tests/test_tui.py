import io
import unittest

from rich.console import Console

from dlms_enum.reporter import summary_lines
from dlms_enum.tui import ScanUI


class ScanUITests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
