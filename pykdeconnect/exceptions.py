from __future__ import annotations

from pykdeconnect.plugin import Plugin


class NotConnectedError(Exception):
    def __init__(self) -> None:
        super().__init__("Device isn't connected to peer")


class PluginRegistryLockedError(Exception):
    def __init__(self) -> None:
        super().__init__(
            "Tried to register a plugin after registry got locked. "
            "Register your plugins before starting the client"
        )


class PluginAlreadyRegisteredError(Exception):
    def __init__(self, plugin_class: type[Plugin]) -> None:
        super().__init__(f'Plugin {plugin_class.__name__} is already registered')


class PluginNotRegisteredError(Exception):
    def __init__(self) -> None:
        super().__init__("Tried to load plugin that wasn't registered")


class PayloadAlreadyRegisteredError(Exception):
    incoming: bool

    def __init__(self, payloads: set[str], *, incoming: bool) -> None:
        super().__init__(
            f"A plugin {'receiving' if incoming else 'sending'} the following payloads is already "
            f"registered: "
            + ", ".join(payloads)
        )

        self.incoming = incoming


class IncompatiblePluginError(Exception):
    incoming: bool

    def __init__(self, *, incoming: bool) -> None:
        if incoming:
            msg = "This plugin receives payloads not supported by this device"
        else:
            msg = "Device doesn't support all payloads sent by this plugin"
        super().__init__(msg)

        self.incoming = incoming
