from dataclasses import dataclass

from .encode import DataclassEncoder
from .decode import DataclassDecoder


@dataclass
class A:
    a: int
    b: str


@dataclass
class B:
    c: int
    d: str
    e: A


def main():
    encoder = DataclassEncoder("type", {"test.A": A, "test.B": B})
    decoder = DataclassDecoder("type", {"test.A": A, "test.B": B})
    a = A(1, "foo")
    b = B(2, "bar", a)
    str_a = encoder.encode(a)
    str_b = encoder.encode(b)
    print(str_a)
    print(str_b)
    new_a = decoder.decode(str_a)
    new_b = decoder.decode(str_b)
    print(new_a)
    print(new_b)



if __name__ == '__main__':
    main()
