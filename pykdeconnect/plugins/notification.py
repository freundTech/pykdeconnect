import uuid
from typing import Set, TypedDict

from typing_extensions import NotRequired, Required

from pykdeconnect.devices import KdeConnectDevice
from pykdeconnect.helpers import get_timestamp
from pykdeconnect.payloads import Payload
from pykdeconnect.plugin import Plugin


class NotificationPayloadBody(TypedDict, total=False):
    id: Required[str]
    actions: list[str]
    isCancel: bool
    onlyOnce: bool
    isClearable: bool
    appName: str
    time: int
    ticker: str
    title: str
    text: str
    payloadHash: str


class NotificationPayload(Payload):
    body: NotificationPayloadBody


class NotificationReceiverPlugin(Plugin):
    @classmethod
    def get_incoming_payload_types(cls) -> Set[str]:
        return {"kdeconnect.notification"}

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[str]:
        return {
            "kdeconnect.notification.request",
            "kdeconnect.notification.reply",
            "kdeconnect.notification.action"
        }

    @classmethod
    def create_instance(cls, device: KdeConnectDevice) -> Plugin:
        return cls(device)

    async def handle_payload(self, payload: Payload) -> None:
        print(payload)


class NotificationSenderPlugin(Plugin):
    @classmethod
    def get_incoming_payload_types(cls) -> Set[str]:
        return {"kdeconnect.notification.request"}

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[str]:
        return {"kdeconnect.notification"}

    @classmethod
    def create_instance(cls, device: KdeConnectDevice) -> Plugin:
        return cls(device)

    async def send_notification(self, title: str, text: str, /, ticker: str = None):
        if ticker is None:
            ticker = f"{title}: {text}"
        payload: NotificationPayload = {
            "id": get_timestamp(),
            "type": "kdeconnect.notification",
            "body": {
                id: uuid.uuid4(),
                title: title,
                text: text,
                ticker: ticker
            }

        }

        await self.device.send_payload(payload)

    async def handle_payload(self, payload: Payload) -> None:
        pass

