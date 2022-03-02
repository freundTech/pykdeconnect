"""
A small library for automagically converting TypedDicts into voluptuous schemas.
Might be published as a standalone library later.
"""
from __future__ import annotations

import sys
from functools import lru_cache
from types import GenericAlias

from typing_extensions import is_typeddict  # type: ignore
from typing_extensions import Annotated
from typing_extensions import NotRequired as NotRequired_ex
from typing_extensions import Required as Required_ex
from typing_extensions import get_args, get_origin

from typing import (  # type: ignore # isort: skip
    Any, Callable, Literal, Tuple, Type, TypeVar, Union,
    _GenericAlias, _SpecialGenericAlias, _TypedDictMeta, cast, get_type_hints
)

if sys.version_info >= (3, 10):
    from types import UnionType
    union = (Union, UnionType)
    generic_aliases = (GenericAlias, _GenericAlias, UnionType)
else:
    union = (Union,)
    generic_aliases = (GenericAlias, _GenericAlias)

if sys.version_info >= (3, 11):
    HAS_REQUIRED = True
    from typing import NotRequired, Required
    required = (Required, Required_ex)
    not_required = (NotRequired, NotRequired_ex)
else:
    HAS_REQUIRED = False
    required = (Required_ex,)
    not_required = (NotRequired_ex,)

import voluptuous as vol  # type: ignore

simple_aliases = {list, set, frozenset}


def no_extra(x: str) -> str:
    return x


class Vol:
    schema: Any

    def __init__(self, schema: Any):
        self.schema = schema


@lru_cache
def typed_dict_to_schema(typed_dict: _TypedDictMeta):
    def typed_dict_to_schema_dict(typed_dict: _TypedDictMeta):
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
            if origin in simple_aliases:
                return origin([convert_type(args[0])]), no_extra
            elif origin in not_required:
                typ, _ = convert_type(args[0])
                return typ, vol.Optional
            elif origin in required:
                typ, _ = convert_type(args[0])
                return typ, vol.Required
            elif origin in union:
                types = (convert_type(t)[0] for t in args)
                return vol.Any(*types), no_extra
            elif origin == Literal:
                return args[0], no_extra
            elif origin == Annotated:
                validators = [convert_type(args[0])[0]]
                for v in args[1:]:
                    if isinstance(v, Vol):
                        validators.append(v.schema)
                return vol.All(*validators), no_extra
        elif isinstance(typ, _SpecialGenericAlias):
            origin = get_origin(typ)
            if origin in simple_aliases:
                return origin, no_extra
        elif is_typeddict(typ):
            if typ == typed_dict:
                return vol.Self, no_extra
            return typed_dict_to_schema_dict(typ), no_extra
        elif typ == Any:
            return object, no_extra
        elif isinstance(typ, type):
            return typ, no_extra
        raise ValueError("Don't know how to handle type annotation ", typ)

    schema = typed_dict_to_schema_dict(typed_dict)

    return vol.Schema(schema, required=typed_dict.__total__)


T = TypeVar('T')


# TODO: This should use TypeForm[T] -> T instead of Type[T] -> Any, but TypeForm is work in
# progress: https://github.com/python/mypy/issues/9773
def verify_typed_dict(value: Any, typed_dict: Type[T]) -> Any:
    schema = typed_dict_to_schema(typed_dict)  # type: ignore[arg-type]
    new_value = schema(value)

    return cast(T, new_value)
