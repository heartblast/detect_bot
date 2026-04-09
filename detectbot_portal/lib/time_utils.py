from __future__ import annotations

from datetime import date, datetime, time, timezone
from zoneinfo import ZoneInfo

import pandas as pd


KST = ZoneInfo("Asia/Seoul")
UTC = timezone.utc


def _coerce_datetime(value):
    if value is None or value == "":
        return None
    if isinstance(value, pd.Timestamp):
        return value.to_pydatetime()
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, time.min)

    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def to_display_datetime(value, *, target_tz=KST, assume_naive_tz=UTC):
    dt = _coerce_datetime(value)
    if dt is None:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=assume_naive_tz)

    return dt.astimezone(target_tz)


def format_display_datetime(
    value,
    *,
    target_tz=KST,
    assume_naive_tz=UTC,
    include_tz=True,
    empty="-",
):
    dt = to_display_datetime(value, target_tz=target_tz, assume_naive_tz=assume_naive_tz)
    if dt is None:
        return empty

    suffix = f" {dt.tzname()}" if include_tz and dt.tzname() else ""
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')}{suffix}"
