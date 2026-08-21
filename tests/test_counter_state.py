import json
import tempfile
import unittest
from pathlib import Path

from dlms_enum.counter_state import (
    InvocationCounterError,
    acquire_counter_lease,
    counter_identity,
)


def identity():
    return counter_identity(
        meter_identity="METER-1",
        client_system_title=b"CLIENT01",
        client_address=1,
        server_address=1,
    )


class CounterStateTests(unittest.TestCase):
    def test_meter_counter_n_allocates_strictly_greater_first_counter(self):
        with tempfile.TemporaryDirectory() as directory:
            lease = acquire_counter_lease(
                Path(directory) / "counters.json",
                identity(),
                meter_reported_counter=100,
            )
            try:
                self.assertEqual(lease.next_counter, 101)
            finally:
                lease.close()

    def test_restart_never_rolls_counter_backward(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "counters.json"
            lease = acquire_counter_lease(path, identity(), meter_reported_counter=100)
            lease.persist_next(109)
            lease.close()

            restarted = acquire_counter_lease(path, identity(), meter_reported_counter=102)
            try:
                self.assertEqual(restarted.next_counter, 109)
            finally:
                restarted.close()

    def test_meter_ahead_of_persisted_state_advances_to_meter_plus_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "counters.json"
            lease = acquire_counter_lease(path, identity(), meter_reported_counter=10)
            lease.close()

            advanced = acquire_counter_lease(
                path, identity(), meter_reported_counter=20
            )
            try:
                self.assertEqual(advanced.next_counter, 21)
                state = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(
                    state["records"][advanced.identity_key]["next_counter"], 21
                )
            finally:
                advanced.close()

    def test_persistence_is_atomic_json_and_backward_updates_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "counters.json"
            lease = acquire_counter_lease(path, identity(), meter_reported_counter=7)
            lease.persist_next(9)
            state = json.loads(path.read_text(encoding="utf-8"))
            record = state["records"][lease.identity_key]
            self.assertEqual(record["next_counter"], 9)
            with self.assertRaisesRegex(InvocationCounterError, "backward"):
                lease.persist_next(8)
            lease.close()

    def test_missing_public_counter_requires_explicit_override(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "counters.json"
            with self.assertRaisesRegex(InvocationCounterError, "unsafe_override"):
                acquire_counter_lease(path, identity(), meter_reported_counter=None)
            lease = acquire_counter_lease(
                path, identity(), meter_reported_counter=None, unsafe_override=500
            )
            try:
                self.assertEqual(lease.next_counter, 500)
            finally:
                lease.close()


if __name__ == "__main__":
    unittest.main()
