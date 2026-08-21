"""Generic collection, iterable, and object helpers."""

from __future__ import annotations

import inspect
from itertools import islice
import json
from typing import Any, Callable, Iterable


def unique_value(iterable):
    values = set(iterable)
    if len(values) != 1:
        raise ValueError("The iterable does not contain a unique value")
    return values.pop()


def getattr_recursively(obj: Any, attr: str) -> Any:
    for a in attr.split("."):
        obj = getattr(obj, a)
    return obj


def batched(iterable: Iterable, n: int):
    it = iter(iterable)
    while batch := tuple(islice(it, n)):
        yield batch


def get_scale_fn(scale: float) -> Callable[[int], float]:
    return lambda x: int(round(x * scale))


def object_from_superset_of_constructor_kwds(cls, **kwds) -> Any:
    kwds = {k: v for k, v in kwds.items() if k in inspect.getfullargspec(cls.__init__).args}
    return cls(**kwds)


def compose_functions(*funcs):
    def inner(arg):
        result = arg
        for func in funcs:
            result = func(result)
        return result
    return inner


def get_max_keys_from_dict(d: dict[str, int]) -> tuple[str]:
    keys = []
    val = -1
    for k, v in d.items():
        if v >= val:
            if v > val:
                keys = []
            keys.append(k)
            val = v

    return tuple(keys)


def is_jsonable(x: Any) -> bool:
    try:
        json.dumps(x)
        return True
    except (TypeError, OverflowError):
        return False


def flatten(xs):
    for x in xs:
        if isinstance(x, Iterable) and not isinstance(x, (str, bytes)):
            yield from flatten(x)
        else:
            yield x
