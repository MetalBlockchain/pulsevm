import importlib.util
import pathlib
import struct
import unittest


SCRIPT = pathlib.Path(__file__).with_name("plw-replay.py")
SPEC = importlib.util.spec_from_file_location("plw_replay", SCRIPT)
plw_replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plw_replay)


class WalDamageScanTests(unittest.TestCase):
    def candidate(self, revision, table_count, payload_len=64):
        data = bytearray(8 + payload_len + 32)
        struct.pack_into("<Q", data, 0, payload_len)
        struct.pack_into("<qQ", data, 8, revision, table_count)
        return bytes(data)

    def test_unrelated_prefix_does_not_consume_hash_budget(self):
        old_budget = plw_replay.BUDGET
        try:
            plw_replay.BUDGET = 1
            data = self.candidate(10, 99)
            self.assertIsNone(
                plw_replay._valid_follows(data, 0, b"k" * 32, (10, 7))
            )
        finally:
            plw_replay.BUDGET = old_budget

    def test_plausible_prefix_consumes_budget_even_when_digest_is_bad(self):
        old_budget = plw_replay.BUDGET
        try:
            plw_replay.BUDGET = 1
            data = self.candidate(11, 7)
            self.assertEqual(
                plw_replay._valid_follows(data, 0, b"k" * 32, (10, 7)),
                "BUDGET",
            )
        finally:
            plw_replay.BUDGET = old_budget


if __name__ == "__main__":
    unittest.main()
