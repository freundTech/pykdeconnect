class NotConnectedError(Exception):
    def __init__(self) -> None:
        super().__init__("Device isn't connected to peer")


class IncompatiblePluginError(Exception):
    pass
