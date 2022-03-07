from __future__ import annotations

import importlib
from collections import defaultdict
from typing import TYPE_CHECKING, Optional, Set, Type, TypeVar, cast

from .exceptions import IncompatiblePluginError
from .plugin import Plugin

if TYPE_CHECKING:
    from .devices import KdeConnectDevice

P = TypeVar('P', bound=Plugin)
T = TypeVar('T')


builtins_plugins = [
    "pykdeconnect.plugins.ping.PingReceiverPlugin",
    "pykdeconnect.plugins.ping.PingSenderPlugin",
    "pykdeconnect.plugins.battery.BatteryReceiverPlugin",
]


class PluginRegistry:
    plugins: Set[Type[Plugin]]
    incoming_payloads: Set[str]
    outgoing_payloads: Set[str]

    _plugin_map: dict[str, Type[Plugin]]

    _plugin_instances: dict[KdeConnectDevice, dict[Type[Plugin], Plugin]]

    _locked: bool = False

    def __init__(self, load_builtin_plugins: bool = True):
        self.plugins = set()
        self.incoming_payloads = set()
        self.outgoing_payloads = set()

        self._plugin_map = {}
        self._plugin_instances = defaultdict(dict)

        if load_builtin_plugins:
            for plugin_name in builtins_plugins:
                module_name, _, plugin_name = plugin_name.rpartition(".")
                module = importlib.import_module(module_name)
                plugin = getattr(module, plugin_name)
                self.register_plugin(plugin)

    def register_plugin(self, plugin_type: Type[Plugin]) -> None:
        if self._locked:
            raise Exception("Tried to register a plugin after registry got locked. "
                            "Register your plugins before starting the client")
        if plugin_type in self.plugins:
            raise Exception("Plugin is already registered")
        incoming_payloads = plugin_type.get_incoming_payload_types()
        outgoing_payloads = plugin_type.get_outgoing_payload_types()
        incoming_intersection = self.incoming_payloads.intersection(incoming_payloads)
        if len(incoming_intersection) != 0:
            raise Exception("A plugin receiving the following payloads is already registered: " +
                            ", ".join(incoming_intersection))

        outgoing_intersection = self.outgoing_payloads.intersection(outgoing_payloads)
        if len(outgoing_intersection) != 0:
            raise Exception("A plugin receiving the following payloads is already registered: " +
                            ", ".join(outgoing_intersection))

        self.incoming_payloads |= incoming_payloads
        self.outgoing_payloads |= outgoing_payloads
        for payload in incoming_payloads:
            self._plugin_map[payload] = plugin_type
        self.plugins.add(plugin_type)

    def lock(self) -> None:
        self._locked = True

    def get_plugin(self, device: KdeConnectDevice, plugin_class: Type[P]) -> P:
        if plugin_class not in self.plugins:
            raise RuntimeError("Tried to load plugin that wasn't registered")

        if plugin_class not in self._plugin_instances[device]:
            self._check_plugin_compatibility(device, plugin_class)
            self._plugin_instances[device][plugin_class] = plugin_class.create_instance(device)

        return cast(P, self._plugin_instances[device][plugin_class])

    def get_plugin_for_type(self, device: KdeConnectDevice, payload_type: str) -> Optional[Plugin]:
        plugin_class = self._plugin_map.get(payload_type, None)
        if plugin_class is None:
            return None

        return self.get_plugin(device, plugin_class)

    def is_plugin_compatible(self, device: KdeConnectDevice, plugin_class: Type[Plugin]) -> bool:
        try:
            self._check_plugin_compatibility(device, plugin_class)
        except IncompatiblePluginError:
            return False
        else:
            return True

    @staticmethod
    def _check_plugin_compatibility(device: KdeConnectDevice, plugin_class: Type[Plugin]) -> None:
        if not all(
                payload in device.incoming_capabilities
                for payload in plugin_class.get_outgoing_payload_types()
        ):
            raise IncompatiblePluginError(
                "Device doesn't support all payloads sent by this plugin"
            )
        if not all(
                payload in device.outgoing_capabilities
                for payload in plugin_class.get_incoming_payload_types()
        ):
            raise IncompatiblePluginError(
                "This plugin receives payloads not supported by this device"
            )
