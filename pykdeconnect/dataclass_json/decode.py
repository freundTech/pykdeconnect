import dataclasses
from dataclasses import is_dataclass
from json import JSONDecoder
from typing import Any, Dict, TypeVar, overload


class DataclassDecoder:
    type_field: str
    allow_dicts: bool
    type_map: Dict[str, type]

    json_decoder: JSONDecoder

    def __init__(self, type_field: str, type_map: Dict[str, type], allow_dicts: bool = False):
        super().__init__()
        self.type_field = type_field
        self.allow_dicts = allow_dicts
        if type_map is None:
            self.type_map = {}
        else:
            for value in type_map.values():
                if not is_dataclass(value):
                    raise ValueError('Types in "type_map" must be dataclasses')
            self.type_map = dict(type_map)

        self.json_decoder = JSONDecoder()

    T = TypeVar('T', bound=type)
    @overload
    def decode(self, s: str, type_: T) -> T: ...

    @overload
    def decode(self, s: str, type_: None = None) -> Any: ...

    def decode(self, s: str, type_: T | None = None) -> Any:
        obj = self.json_decoder.decode(s)
        return self.value_to_dataclass(obj, type_)

    def type_function(self, dictionary: dict) -> type:
        pass

    def value_to_dataclass(self, value: Any, type_: type | None) -> Any:
        if not isinstance(value, dict):
            return value

        dictionary = value

        if self.type_field in dictionary:
            class_key = dictionary[self.type_field]
            if class_key not in self.type_map:
                raise ValueError(f'No class registered for key "{class_key}')
            class_ = self.type_map[class_key]
            if type_ is not None and class_ != type_:
                raise ValueError(f'Type field "{class_key}" doesn\'t match expected type "{type_}"')
            del dictionary[self.type_field]
        elif type_ is not None:
            class_ = type_
        elif self.allow_dicts:
            return dictionary
        else:
            raise ValueError(f'JSON Object doesn\'t contain type field "{self.type_field}"')

        if not is_dataclass(class_):
            raise ValueError(f'Tried to decode non dataclass "{class_}"')

        for name, field in class_.__dataclass_fields__.items():  # type: ignore[attr-defined]
            if name in dictionary:
                dictionary[name] = self.value_to_dataclass(dictionary[name], field.type)
            elif field.default is not dataclasses.MISSING:
                dictionary[name] = field.default
            else:
                raise ValueError(f'JSON is missing key "{name}", but it is required by class "{class_}"')


        return class_(**dictionary)
