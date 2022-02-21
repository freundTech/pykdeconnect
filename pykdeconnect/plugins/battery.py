import asyncio
from asyncio import Future
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Awaitable, Callable, Optional, Set, Type

from pykdeconnect.dataclass_json import Flags
from pykdeconnect.devices import KdeConnectDevice
from pykdeconnect.payloads import Payload
from pykdeconnect.plugin import Plugin


class BatteryThreshold(Enum):
    NONE = 0
    LOW = 1


@dataclass
class BatteryState:
    current_charge: int
    charging: bool
    low: bool


@dataclass
class BatteryPayload(Payload):
    @dataclass
    class Body:
        currentCharge: int
        isCharging: bool
        thresholdEvent: int
        batteryQuantity: Annotated[Optional[int], Flags.REMOVE_IF_NONE] = None

    body: Body

    @classmethod
    def get_type(cls) -> str:
        return "kdeconnect.battery"


@dataclass
class BatteryRequestPayload(Payload):
    @dataclass
    class Body:
        request: bool

    body: Body

    @classmethod
    def get_type(cls) -> str:
        return "kdeconnect.battery.request"


BatteryChargeCallback = Callable[[int], Awaitable[None]]
BatteryChargingCallback = Callable[[bool], Awaitable[None]]
BatteryLowCallback = Callable[[bool], Awaitable[None]]


class BatteryReceiverPlugin(Plugin):
    current_charge: Optional[int]
    charging: Optional[bool]

    battery_request_future: Optional[Future[BatteryState]] = None
    battery_charge_changed_callbacks: Set[BatteryChargeCallback]
    battery_charging_changed_callbacks: Set[BatteryChargingCallback]
    battery_low_changed_callbacks: Set[BatteryLowCallback]

    def __init__(self, device: 'KdeConnectDevice'):
        super().__init__(device)
        self.battery_charge_changed_callbacks = set()
        self.battery_charging_changed_callbacks = set()
        self.battery_low_changed_callbacks = set()

    @classmethod
    def get_incoming_payload_types(cls) -> Set[Type[Payload]]:
        return {BatteryPayload}

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[Type[Payload]]:
        return {BatteryRequestPayload}

    @classmethod
    def create_instance(cls, device: KdeConnectDevice):
        return cls(device)

    async def handle_payload(self, payload):
        assert isinstance(payload, BatteryPayload)
        charge = payload.body.currentCharge
        charging = payload.body.isCharging
        low = payload.body.thresholdEvent == BatteryThreshold.LOW

        if self.battery_request_future is not None:
            self.battery_request_future.set_result(BatteryState(charge, charging, low))
            self.battery_request_future = None

        callbacks = {callback(charge) for callback in self.battery_charge_changed_callbacks}
        callbacks |= {callback(charging) for callback in self.battery_charging_changed_callbacks}
        callbacks |= {callback(low) for callback in self.battery_low_changed_callbacks}

        await asyncio.gather(*callbacks)

    async def request_battery(self):
        request_payload = BatteryRequestPayload(BatteryRequestPayload.Body(True))
        if self.device.is_connected:
            assert self.device.protocol is not None
            self.device.protocol.send_payload(request_payload)

    async def get_battery_state(self) -> BatteryState:
        loop = asyncio.get_running_loop()
        self.battery_request_future = loop.create_future()
        await self.request_battery()

        return await self.battery_request_future

    def register_charge_changed_callback(self, callback: BatteryChargeCallback):
        self.battery_charge_changed_callbacks.add(callback)

    def unregister_charge_changed_callback(self, callback: BatteryChargeCallback):
        self.battery_charge_changed_callbacks.remove(callback)

    def register_charging_changed_callback(self, callback: BatteryChargingCallback):
        self.battery_charging_changed_callbacks.add(callback)

    def unregister_charging_changed_callback(self, callback: BatteryChargingCallback):
        self.battery_charging_changed_callbacks.remove(callback)

    def register_low_changed_callback(self, callback: BatteryLowCallback):
        self.battery_low_changed_callbacks.add(callback)

    def unregister_low_changed_callback(self, callback: BatteryLowCallback):
        self.battery_low_changed_callbacks.remove(callback)
