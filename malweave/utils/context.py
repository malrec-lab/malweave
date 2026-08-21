"""Context managers and decorators for warnings and stdout/stderr suppression."""

from __future__ import annotations

import contextlib
from functools import wraps
import os
import warnings


@contextlib.contextmanager
def print_context(suppress: bool = False, suppress_warnings: bool = True):
    if not suppress:
        yield
    else:
        with open(os.devnull, "w") as f, contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            if suppress_warnings:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    yield
            else:
                yield


def ignore_warnings_decorator(*filter_args, **filter_kwargs):

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with warnings.catch_warnings():
                warnings.filterwarnings(*filter_args, **filter_kwargs)
                return func(*args, **kwargs)

        return wrapper

    return decorator
