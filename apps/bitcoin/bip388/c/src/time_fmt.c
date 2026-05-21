#include "../include/bip388.h"

#include <stdio.h>

/* Howard Hinnant civil-from-days; mirrors src/time.rs (forward only). */
size_t bip388_format_utc_date(uint32_t timestamp, char *out, size_t cap) {
    uint32_t days = timestamp / 86400u;
    uint32_t time_of_day = timestamp % 86400u;
    int64_t z = (int64_t)days + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    uint32_t doe = (uint32_t)(z - era * 146097);
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = (int64_t)yoe + era * 400;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint32_t mp = (5 * doy + 2) / 153;
    uint32_t d = doy - (153 * mp + 2) / 5 + 1;
    uint32_t m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y += 1;

    char buf[32];
    int n;
    if (time_of_day == 0) {
        n = snprintf(buf, sizeof(buf), "%04lld-%02u-%02u", (long long)y, m, d);
    } else {
        uint32_t h = time_of_day / 3600u;
        uint32_t mi = (time_of_day % 3600u) / 60u;
        uint32_t sec = time_of_day % 60u;
        n = snprintf(buf, sizeof(buf), "%04lld-%02u-%02u %02u:%02u:%02u",
                     (long long)y, m, d, h, mi, sec);
    }
    if (n < 0) return 0;
    if (cap >= (size_t)n + 1) {
        for (int i = 0; i < n; ++i) out[i] = buf[i];
        out[n] = '\0';
    }
    return (size_t)n;
}

size_t bip388_format_seconds(uint32_t secs, char *out, size_t cap) {
    uint32_t days = secs / 86400u;
    uint32_t hours = (secs % 86400u) / 3600u;
    uint32_t minutes = (secs % 3600u) / 60u;
    uint32_t seconds = secs % 60u;
    char buf[64];
    int n = 0;
    if (days) n += snprintf(buf + n, sizeof(buf) - n, "%s%ud", n ? " " : "", days);
    if (hours) n += snprintf(buf + n, sizeof(buf) - n, "%s%uh", n ? " " : "", hours);
    if (minutes) n += snprintf(buf + n, sizeof(buf) - n, "%s%um", n ? " " : "", minutes);
    if (seconds) n += snprintf(buf + n, sizeof(buf) - n, "%s%us", n ? " " : "", seconds);
    if (n == 0) {
        buf[0] = '0'; buf[1] = 's'; buf[2] = '\0'; n = 2;
    }
    if (cap >= (size_t)n + 1) {
        for (int i = 0; i <= n; ++i) out[i] = buf[i];
    }
    return (size_t)n;
}
