#include "../include/bip388.h"
#include "test_framework.h"

static void check_date(uint32_t ts, const char *expected) {
    char buf[64];
    size_t n = bip388_format_utc_date(ts, buf, sizeof(buf));
    T_EQ_UINT(n, strlen(expected));
    T_EQ_STR(buf, expected);
}

static void check_secs(uint32_t s, const char *expected) {
    char buf[64];
    size_t n = bip388_format_seconds(s, buf, sizeof(buf));
    T_EQ_UINT(n, strlen(expected));
    T_EQ_STR(buf, expected);
}

TEST(format_utc_date_known) {
    check_date(0, "1970-01-01");
    check_date(86400, "1970-01-02");
    check_date(86399, "1970-01-01 23:59:59");
    check_date(500000000, "1985-11-05 00:53:20");
    check_date(1700000000, "2023-11-14 22:13:20");
    check_date(1609459200, "2021-01-01");
    check_date(1582934400, "2020-02-29");
}

TEST(format_seconds_known) {
    check_secs(0, "0s");
    check_secs(1, "1s");
    check_secs(60, "1m");
    check_secs(3600, "1h");
    check_secs(86400, "1d");
    check_secs(512, "8m 32s");
    check_secs(92160, "1d 1h 36m");
    check_secs(90061, "1d 1h 1m 1s");
    check_secs(93784, "1d 2h 3m 4s");
    check_secs(3601, "1h 1s");
}
