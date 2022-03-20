from pykdeconnect.const import KdeConnectDeviceType


def test_device_type_alias():
    assert KdeConnectDeviceType("smartphone") == KdeConnectDeviceType.PHONE
    assert KdeConnectDeviceType("phone") == KdeConnectDeviceType.PHONE


def test_device_type_unknown():
    assert KdeConnectDeviceType("foobar") == KdeConnectDeviceType.UNKNOWN
