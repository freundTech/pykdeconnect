import importlib
from typing import Optional, Set, Type, TypeVar

from pykdeconnect.devices import KdeConnectDevice
from pykdeconnect.plugin import Plugin

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

    _locked: bool = False

    def __init__(self, load_builtin_plugins: bool = True):
        self.plugins = set()
        self.incoming_payloads = set()
        self.outgoing_payloads = set()

        self._plugin_map = {}

        if load_builtin_plugins:
            for plugin_name in builtins_plugins:
                module_name, _, plugin_name = plugin_name.rpartition(".")
                module = importlib.import_module(module_name)
                plugin = getattr(module, plugin_name)
                self.register_plugin(plugin)

    def register_plugin(self, plugin_type: Type[Plugin]):
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

    def lock(self):
        self._locked = True

    def get_plugin(self, device: KdeConnectDevice, plugin_class: Type[P], force_load=False) -> P:
        if plugin_class not in self.plugins:
            raise RuntimeError("Tried to load plugin that wasn't registered")

        return device.get_plugin(plugin_class, force_load)

    def get_plugin_for_type(self, device: KdeConnectDevice, payload_type: str) -> Optional[Plugin]:
        plugin_class = self._plugin_map.get(payload_type)
        if plugin_class is None:
            return None

        return self.get_plugin(device, plugin_class)
