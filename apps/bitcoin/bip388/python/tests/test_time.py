"""Port of `src/time.rs` forward-direction tests."""

import unittest

from bip388.time_fmt import format_seconds, format_utc_date


class TestFormatUtcDate(unittest.TestCase):
    def test_known(self):
        self.assertEqual(format_utc_date(0), "1970-01-01")
        self.assertEqual(format_utc_date(86400), "1970-01-02")
        self.assertEqual(format_utc_date(86399), "1970-01-01 23:59:59")
        self.assertEqual(format_utc_date(500_000_000), "1985-11-05 00:53:20")
        self.assertEqual(format_utc_date(1_700_000_000), "2023-11-14 22:13:20")
        self.assertEqual(format_utc_date(1_609_459_200), "2021-01-01")
        self.assertEqual(format_utc_date(1_582_934_400), "2020-02-29")


class TestFormatSeconds(unittest.TestCase):
    def test_known(self):
        self.assertEqual(format_seconds(0), "0s")
        self.assertEqual(format_seconds(1), "1s")
        self.assertEqual(format_seconds(60), "1m")
        self.assertEqual(format_seconds(3600), "1h")
        self.assertEqual(format_seconds(86400), "1d")
        self.assertEqual(format_seconds(512), "8m 32s")
        self.assertEqual(format_seconds(92160), "1d 1h 36m")
        self.assertEqual(format_seconds(90061), "1d 1h 1m 1s")
        self.assertEqual(format_seconds(93784), "1d 2h 3m 4s")
        self.assertEqual(format_seconds(3601), "1h 1s")


if __name__ == "__main__":
    unittest.main()
