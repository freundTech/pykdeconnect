from enum import Enum, auto
from typing import Any
from typing import _AnnotatedAlias # type: ignore


class Flags(Enum):
    REMOVE_IF_NONE = auto()


def is_remove_if_none(type_: Any) -> bool:
    return isinstance(type_, _AnnotatedAlias) and Flags.REMOVE_IF_NONE in type_.__metadata__