from __future__ import annotations

import asyncio
from asyncio import Future
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Optional

from typing_extensions import NotRequired, TypedDict

from pykdeconnect.devices import KdeConnectDevice
from pykdeconnect.helpers import get_timestamp
from pykdeconnect.payloads import Payload
from pykdeconnect.plugin import Plugin
from pykdeconnect.vol_extra import TypedDictVerifier


class BatteryThreshold(Enum):
    NONE = 0
    LOW = 1


@dataclass
class BatteryState:
    current_charge: int
    charging: bool
    low: bool


class BatteryPayloadBody(TypedDict):
    currentCharge: int
    isCharging: bool
    thresholdEvent: int
    batteryQuantity: NotRequired[int]


class BatteryPayload(Payload):
    body: BatteryPayloadBody


class BatteryRequestBody(TypedDict):
    request: bool


class BatteryRequestPayload(Payload):
    body: BatteryRequestBody


BatteryChargeCallback = Callable[[int], Awaitable[None]]
BatteryChargingCallback = Callable[[bool], Awaitable[None]]
BatteryLowCallback = Callable[[bool], Awaitable[None]]


class BatteryReceiverPlugin(Plugin):
    current_charge: Optional[int]
    charging: Optional[bool]

    battery_request_future: Optional[Future[BatteryState]] = None
    battery_charge_changed_callbacks: set[BatteryChargeCallback]
    battery_charging_changed_callbacks: set[BatteryChargingCallback]
    battery_low_changed_callbacks: set[BatteryLowCallback]

    _payload_verifier: TypedDictVerifier[BatteryPayload]

    def __init__(self, device: KdeConnectDevice):
        super().__init__(device)
        self.battery_charge_changed_callbacks = set()
        self.battery_charging_changed_callbacks = set()
        self.battery_low_changed_callbacks = set()

        self._payload_verifier = TypedDictVerifier[BatteryPayload]()

    @classmethod
    def get_incoming_payload_types(cls) -> set[str]:
        return {"kdeconnect.battery"}

    @classmethod
    def get_outgoing_payload_types(cls) -> set[str]:
        return {"kdeconnect.battery.request"}

    @classmethod
    def create_instance(cls, device: KdeConnectDevice) -> BatteryReceiverPlugin:
        return cls(device)

    async def handle_payload(self, payload: Payload) -> None:
        payload = self._payload_verifier.verify(payload)
        charge = payload["body"]["currentCharge"]
        charging = payload["body"]["isCharging"]
        low = payload["body"]["thresholdEvent"] == BatteryThreshold.LOW.value

        if self.battery_request_future is not None:
            self.battery_request_future.set_result(BatteryState(charge, charging, low))
            self.battery_request_future = None

        callbacks = {callback(charge) for callback in self.battery_charge_changed_callbacks}
        callbacks |= {callback(charging) for callback in self.battery_charging_changed_callbacks}
        callbacks |= {callback(low) for callback in self.battery_low_changed_callbacks}

        await asyncio.gather(*callbacks)

    async def request_battery(self) -> None:
        request_payload: BatteryRequestPayload = {
            "id": get_timestamp(),
            "type": "kdeconnect.battery.request",
            "body": {
                "request": True
            }
        }
        if self.device.is_connected:
            assert self.device.protocol is not None
            self.device.protocol.send_payload(request_payload)

    async def get_battery_state(self) -> BatteryState:
        loop = asyncio.get_running_loop()
        self.battery_request_future = loop.create_future()
        await self.request_battery()

        return await self.battery_request_future

    def register_charge_changed_callback(self, callback: BatteryChargeCallback) -> None:
        self.battery_charge_changed_callbacks.add(callback)

    def unregister_charge_changed_callback(self, callback: BatteryChargeCallback) -> None:
        self.battery_charge_changed_callbacks.remove(callback)

    def register_charging_changed_callback(self, callback: BatteryChargingCallback) -> None:
        self.battery_charging_changed_callbacks.add(callback)

    def unregister_charging_changed_callback(self, callback: BatteryChargingCallback) -> None:
        self.battery_charging_changed_callbacks.remove(callback)

    def register_low_changed_callback(self, callback: BatteryLowCallback) -> None:
        self.battery_low_changed_callbacks.add(callback)

    def unregister_low_changed_callback(self, callback: BatteryLowCallback) -> None:
        self.battery_low_changed_callbacks.remove(callback)
