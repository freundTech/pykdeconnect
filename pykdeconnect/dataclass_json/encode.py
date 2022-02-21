import dataclasses
from dataclasses import is_dataclass
from json import JSONEncoder
from typing import Any, Dict

from .common import is_remove_if_none


class DataclassEncoder(JSONEncoder):
    type_field: str
    allow_unknown_dataclasses: bool
    type_map: Dict[type, str]

    def __init__(self,
                 type_field: str,
                 type_map: Dict[str, type],
                 allow_unknown_dataclasses: bool = True):
        super().__init__()
        self.type_field = type_field
        self.allow_unknown_dataclasses = allow_unknown_dataclasses
        if type_map is None:
            self.type_map = {}
        else:
            for value in type_map.values():
                if not is_dataclass(value):
                    raise ValueError('Types in "type_map" must be dataclasses')
            self.type_map = {v: k for k, v in type_map.items()}

    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            if type(o) in self.type_map:
                result = self.dataclass_to_dict(o)
                result[self.type_field] = self.type_map[type(o)]
                return result
            elif self.allow_unknown_dataclasses:
                return self.dataclass_to_dict(o)
            else:
                raise ValueError(f'No key registered for class "{type(o)}')
        else:
            super().default(o)

    def dataclass_to_dict(self, o: Any) -> dict:
        result = {}
        for field in dataclasses.fields(o):
            value = getattr(o, field.name)
            if not (value is None and is_remove_if_none(field.type)):
                result[field.name] = value

        return result
