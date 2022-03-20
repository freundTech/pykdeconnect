from __future__ import annotations

import sys
from typing import (
    Annotated, Any, FrozenSet, List, Literal, Optional, Set, TypedDict, Union
)

import pytest
import voluptuous as vol
from typing_extensions import NotRequired, Required
from voluptuous import MultipleInvalid

from pykdeconnect.vol_extra import TypedDictVerifier, typed_dict_to_schema


# vol.Any doesn't come with a proper __eq__ method
def patched_any_eq(self: vol.Any, other: object):
    if not isinstance(other, vol.Any):
        return NotImplemented
    return set(self.validators) == set(other.validators)


vol.Any.__eq__ = patched_any_eq


def test_simple_alias():
    class Test(TypedDict):
        a: List
        b: Set
        c: FrozenSet

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        'a': list,
        'b': set,
        'c': frozenset
    }, required=True)


def test_simple_alias_parameterized():
    class Test(TypedDict):
        a: List[int]
        b: Set[str]
        c: FrozenSet[bytes]

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        'a': [int],
        'b': {str},
        'c': frozenset({bytes})
    }, required=True)



def test_required():
    class Test(TypedDict, total=False):
        a: Required[int]

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        vol.Required('a'): int
    }, required=False)


def test_not_required():
    class Test(TypedDict):
        a: NotRequired[int]

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        vol.Optional('a'): int
    }, required=True)


def test_union():
    class Test(TypedDict):
        a: Optional[int]
        b: Union[int, str]

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        'a': vol.Any(int, None),
        'b': vol.Any(int, str),
    }, required=True)


@pytest.mark.skipif(sys.version_info < (3, 10), reason="requires python 3.10 or higher")
def test_new_union():
    class Test(TypedDict):
        a: int | None
        b: int | str

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        'a': vol.Any(int, None),
        'b': vol.Any(int, str)
    }, required=True)


def test_literal():
    # Not tested: Enum. Does voluptuous support enum literals?
    class Test(TypedDict):
        a: Literal[1]
        b: Literal["foo"]
        c: Literal[b"bar"]
        d: Literal[None]

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        'a': 1,
        'b': "foo",
        'c': b"bar",
        'd': None
    })


def test_annotated():
    class Test(TypedDict):
        a: Annotated[int, "foo", 50]

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        'a': int
    })


def test_typeddict():
    class Inner(TypedDict):
        a: int

    # PEP 563 limitation
    globals()["Inner"] = Inner

    class Outer(TypedDict):
        a: Inner

    schema = typed_dict_to_schema(Outer)
    assert schema == vol.Schema({
        'a': {
            'a': int
        }
    })


def test_self():
    class Test(TypedDict):
        a: Test

    # PEP 563 limitation
    globals()["Test"] = Test

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        'a': vol.Self
    })


def test_any():
    class Test(TypedDict):
        a: Any

    schema = typed_dict_to_schema(Test)
    assert schema == vol.Schema({
        'a': object
    })


def test_typed_dict_verifier():
    class Test(TypedDict):
        a: int

    verifier = TypedDictVerifier[Test]()

    verifier.verify({'a': 10})

    with pytest.raises(MultipleInvalid):
        verifier.verify({'a': "foo"})


def test_type_dict_verifier_init():
    with pytest.raises(RuntimeError):
        TypedDictVerifier()
