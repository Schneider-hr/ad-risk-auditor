from .asrep_roasting import detect_asrep_roasting
from .kerberoasting import detect_kerberoasting
from .password_policy import detect_password_policy_weaknesses
from .privileged_sprawl import detect_privileged_group_sprawl
from .stale_accounts import detect_stale_accounts

ALL_DETECTORS = [
    detect_asrep_roasting,
    detect_kerberoasting,
    detect_password_policy_weaknesses,
    detect_stale_accounts,
]

__all__ = [
    "detect_asrep_roasting",
    "detect_kerberoasting",
    "detect_password_policy_weaknesses",
    "detect_privileged_group_sprawl",
    "detect_stale_accounts",
    "ALL_DETECTORS",
]
