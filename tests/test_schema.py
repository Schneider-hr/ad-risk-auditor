from datetime import datetime, timedelta, timezone

from adriskauditor.schema import (
    UF_ACCOUNTDISABLE,
    UF_DONT_REQUIRE_PREAUTH,
    UF_NORMAL_ACCOUNT,
    filetime_to_datetime,
    is_asrep_roastable,
    is_disabled,
    negative_filetime_to_timedelta,
)


def test_filetime_zero_is_never():
    assert filetime_to_datetime(0) is None


def test_filetime_max_sentinel_is_never():
    assert filetime_to_datetime(0x7FFFFFFFFFFFFFFF) is None


def test_filetime_known_value():
    # 132000000000000000 ticks (100ns) after 1601-01-01 -> a known real date.
    # Cross-checked against Microsoft's documented FILETIME conversion.
    result = filetime_to_datetime(132000000000000000)
    assert result is not None
    assert result.year == 2019
    assert result.tzinfo == timezone.utc


def test_filetime_roundtrips_reasonably():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    ticks = int((now - epoch).total_seconds() * 10_000_000)
    result = filetime_to_datetime(ticks)
    assert abs((result - now).total_seconds()) < 1


def test_negative_filetime_zero_is_no_expiry():
    assert negative_filetime_to_timedelta(0) == timedelta(0)


def test_negative_filetime_interval():
    # -864000000000 ticks = -1 day in 100ns units
    result = negative_filetime_to_timedelta(-864000000000)
    assert result == timedelta(days=1)


def test_is_disabled_flag():
    assert is_disabled(UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE) is True
    assert is_disabled(UF_NORMAL_ACCOUNT) is False


def test_is_asrep_roastable_flag():
    assert is_asrep_roastable(UF_NORMAL_ACCOUNT | UF_DONT_REQUIRE_PREAUTH) is True
    assert is_asrep_roastable(UF_NORMAL_ACCOUNT) is False
