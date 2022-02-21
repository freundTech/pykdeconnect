from enum import Enum, auto
from typing import _AnnotatedAlias  # type: ignore
from typing import Any


class Flags(Enum):
    REMOVE_IF_NONE = auto()


def is_remove_if_none(type_: Any) -> bool:
    return isinstance(type_, _AnnotatedAlias) and Flags.REMOVE_IF_NONE in type_.__metadata__
