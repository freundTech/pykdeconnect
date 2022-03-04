"""
A small library for automagically converting TypedDicts into voluptuous schemas.
Might be published as a standalone library later.
"""
from __future__ import annotations

import sys
from types import GenericAlias

# use typing_extensions versions for compatibility with types from typing_extensions
# New in 3.11
# New in 3.10
from typing_extensions import NotRequired as NotRequired_ex
from typing_extensions import Required as Required_ex
from typing_extensions import is_typeddict  # type: ignore
from typing_extensions import get_args, get_origin, get_type_hints

from typing import (  # type: ignore # isort: skip
    Any, Annotated, Callable, Literal, Tuple, Type, TypeVar, Union,
    _GenericAlias, _TypedDictMeta, cast, Generic
)

if sys.version_info >= (3, 10):
    from types import UnionType
    union = (Union, UnionType)
    generic_aliases = (GenericAlias, _GenericAlias, UnionType)
else:
    union = (Union,)
    generic_aliases = (GenericAlias, _GenericAlias)

if sys.version_info >= (3, 11):
    from typing import NotRequired, Required
    required = (Required, Required_ex)
    not_required = (NotRequired, NotRequired_ex)
else:
    required = (Required_ex,)
    not_required = (NotRequired_ex,)

import voluptuous as vol  # type: ignore

_simple_aliases = {list, set, frozenset}


def _no_extra(x: Any) -> Any:
    return x


class Vol:
    schema: Any

    def __init__(self, schema: Any):
        self.schema = schema


def typed_dict_to_schema(typed_dict: _TypedDictMeta) -> vol.Schema:
    def typed_dict_to_schema_dict(typed_dict: _TypedDictMeta) -> dict[Any, Any]:
        res = {}
        for name, typ in get_type_hints(typed_dict, include_extras=True).items():
            typ, extra = convert_type(typ)
            name = extra(name)
            res[name] = typ

        return res

    def convert_type(typ: Any) -> Tuple[Any, Callable[[str], str | vol.Marker]]:
        if isinstance(typ, generic_aliases):
            origin = get_origin(typ)
            args = get_args(typ)
            if origin in _simple_aliases:
                if len(args) == 0:
                    return origin, _no_extra
                else:
                    return origin([convert_type(args[0])]), _no_extra
            elif origin in not_required:
                typ, _ = convert_type(args[0])
                return typ, vol.Optional
            elif origin in required:
                typ, _ = convert_type(args[0])
                return typ, vol.Required
            elif origin in union:
                types = (convert_type(t)[0] for t in args)
                return vol.Any(*types), _no_extra
            elif origin == Literal:
                return args[0], _no_extra
            elif origin == Annotated:
                validators = [convert_type(args[0])[0]]
                for v in args[1:]:
                    if isinstance(v, Vol):
                        validators.append(v.schema)
                return vol.All(*validators), _no_extra
        # Mypy bug: https://github.com/python/mypy/issues/12290
        elif is_typeddict(typ):  # type: ignore[unreachable]
            if typ == typed_dict:
                return vol.Self, _no_extra
            return typed_dict_to_schema_dict(typ), _no_extra
        elif typ == Any:
            return object, _no_extra
        elif isinstance(typ, type):
            return typ, _no_extra
        raise ValueError("Don't know how to handle type annotation ", typ)

    schema = typed_dict_to_schema_dict(typed_dict)

    return vol.Schema(schema, required=typed_dict.__total__)


T = TypeVar('T')


"""
# TODO: This should use TypeForm[T] -> T instead of Type[T] -> Any, but TypeForm is work in
# progress: https://github.com/python/mypy/issues/9773
def verify_typed_dict(value: Any, typed_dict: Type[T]) -> Any:
    schema = typed_dict_to_schema(typed_dict)  # type: ignore[arg-type]
    new_value = schema(value)

    return cast(T, new_value)
"""


class TypedDictVerifier(Generic[T]):
    _schema: vol.Schema

    def __init__(self) -> None:
        raise RuntimeError("This class can't be instantiated directly.")

    def __class_getitem__(cls, typed_dict: Type[T]) -> Any:
        class _TypedDictVerifier(TypedDictVerifier):  # type: ignore[type-arg]
            _typed_dict = typed_dict
            _schema: vol.Schema

            def __init__(self) -> None:
                # Call to parent __init__ intentionally left out
                self._schema = typed_dict_to_schema(self._typed_dict)

            def verify(self, value: Any) -> T:
                new_value = self._schema(value)

                return cast(T, new_value)

        return _TypedDictVerifier

    def verify(self, value: Any) -> T: ...
