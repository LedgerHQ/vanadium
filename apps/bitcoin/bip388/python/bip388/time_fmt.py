"""UTC date and duration formatting for BIP-388 cleartext display.

Mirrors `src/time.rs` of the Rust crate; only the forward (formatting)
direction is included, since the reverse direction is part of the
`cleartext-decode` feature.
"""


def format_utc_date(timestamp: int) -> str:
    """Format a Unix timestamp (u32) as a UTC date or datetime.

    Returns ``"YYYY-MM-DD"`` when the time component is exactly midnight,
    otherwise ``"YYYY-MM-DD HH:MM:SS"``. Uses Howard Hinnant's
    civil-from-days algorithm.
    """
    days = timestamp // 86400
    time_of_day = timestamp % 86400
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    if m <= 2:
        y += 1
    if time_of_day == 0:
        return f"{y:04d}-{m:02d}-{d:02d}"
    h = time_of_day // 3600
    minute = (time_of_day % 3600) // 60
    sec = time_of_day % 60
    return f"{y:04d}-{m:02d}-{d:02d} {h:02d}:{minute:02d}:{sec:02d}"


def format_seconds(secs: int) -> str:
    """Format a number of seconds as a human-readable duration.

    Uses units ``d`` (days), ``h`` (hours), ``m`` (minutes), ``s`` (seconds).
    Returns ``"0s"`` for zero.
    """
    days = secs // 86400
    hours = (secs % 86400) // 3600
    minutes = (secs % 3600) // 60
    seconds = secs % 60
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0:
        parts.append(f"{seconds}s")
    return " ".join(parts) if parts else "0s"
