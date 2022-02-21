import importlib
from typing import Set, Tuple, Type

from pykdeconnect.payloads import Payload, PayloadDecoder, PayloadEncoder
from pykdeconnect.plugin import Plugin

builtins_plugins = [
    "pykdeconnect.plugins.ping.PingReceiverPlugin",
    "pykdeconnect.plugins.ping.PingSenderPlugin",
    "pykdeconnect.plugins.battery.BatteryReceiverPlugin",
]


class PluginRegistry:
    plugins: Set[Type[Plugin]]
    incoming_payloads: Set[Type[Payload]]
    outgoing_payloads: Set[Type[Payload]]

    def __init__(self, load_builtin_plugins: bool = True):
        self.plugins = set()
        self.incoming_payloads = set()
        self.outgoing_payloads = set()

        if load_builtin_plugins:
            for plugin_name in builtins_plugins:
                module_name, _, plugin_name = plugin_name.rpartition(".")
                module = importlib.import_module(module_name)
                plugin = getattr(module, plugin_name)
                self.register_plugin(plugin)

    def register_plugin(self, plugin_type: Type[Plugin]):
        if plugin_type in self.plugins:
            raise Exception("Plugin is already registered")
        incoming_payloads = plugin_type.get_incoming_payload_types()
        outgoing_payloads = plugin_type.get_outgoing_payload_types()
        incoming_intersection = self.incoming_payloads.intersection(incoming_payloads)
        if len(incoming_intersection) != 0:
            raise Exception("A plugin receiving the following payloads is already registered: " +
                            ", ".join(p.get_type() for p in incoming_intersection))

        outgoing_intersection = self.outgoing_payloads.intersection(outgoing_payloads)
        if len(outgoing_intersection) != 0:
            raise Exception("A plugin receiving the following payloads is already registered: " +
                            ", ".join(p.get_type() for p in outgoing_intersection))

        self.incoming_payloads |= incoming_payloads
        self.outgoing_payloads |= outgoing_payloads
        self.plugins.add(plugin_type)

    def get_encoder_decoder_pair(self) -> Tuple[PayloadEncoder, PayloadDecoder]:
        encoder = PayloadEncoder(self.incoming_payloads | self.outgoing_payloads)
        decoder = PayloadDecoder(self.incoming_payloads | self.outgoing_payloads)

        return encoder, decoder
