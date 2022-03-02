from __future__ import annotations

from enum import Enum, IntEnum, auto


class KdeConnectProtocolVersion(IntEnum):
    V6 = 6
    V7 = 7


class KdeConnectDeviceType(Enum):
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    PHONE = "phone"
    TABLET = "tablet"
    TV = "tv"
    UNKNOWN = "unknown"

    def __missing__(self, key: str) -> KdeConnectDeviceType:
        # TODO: Change return type to Self once mypy supports it
        if key == "smartphone":  # Alternative name
            return KdeConnectDeviceType.PHONE
        else:
            return KdeConnectDeviceType.UNKNOWN


class PairingResult(Enum):
    ACCEPTED = auto()
    REJECTED = auto()
    TIMEOUT = auto()


ADDRESS_BROADCAST = "255.255.255.255"
KDECONNECT_PORT = 1716
KDECONNECT_PORT_MIN = 1716
KDECONNECT_PORT_MAX = 1764
MIN_PROTOCOL_VERSION = KdeConnectProtocolVersion.V6
