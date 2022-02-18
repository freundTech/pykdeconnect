from itertools import chain
from typing import List, Sequence, Set, Type

from .payloads import Payload
from .plugins.plugin import Plugin
from .plugins.ping import PingReceiverPlugin, PingSenderPlugin

default_plugins: List[Type[Plugin]] = [
    PingReceiverPlugin,
    PingSenderPlugin,
]


class PluginRegistry:
    plugins: Set[Type[Plugin]]
    payloads: Set[Payload]

    def __init__(self):
        self.plugins = set()
        self.payloads = set()

        for plugin in default_plugins:
            self.register_plugin(plugin)

    def register_plugin(self, plugin: Type[Plugin]):
        self.plugins.add(plugin)
        for payload in chain(plugin.get_incoming_payloads(), plugin.get_outgoing_payloads()):
            self.register_payload(payload)

    def register_payload(self, payload):
        self.payloads.add(payload)
