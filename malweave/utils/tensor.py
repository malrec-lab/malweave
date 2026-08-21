"""Tensor, array, and model-parameter helpers."""

from __future__ import annotations

import random
from typing import Literal

import numpy as np
import torch
from torch import nn, LongTensor, Tensor


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.random.manual_seed(seed)


def nanmax(x: Tensor) -> Tensor:
    min_value = torch.finfo(x.dtype).min
    output = x.nan_to_num(min_value).max()
    return output


def nanmin(x: Tensor) -> Tensor:
    max_value = torch.finfo(x.dtype).max
    output = x.nan_to_num(max_value).min()
    return output


def torch_safe_downcast(x: Tensor) -> Tensor:

    if x.dtype in (torch.int64, torch.int32, torch.int16, torch.int8):
        mx = torch.max(x)
        mn = torch.min(x)

        if mx <= torch.iinfo(torch.int8).max and mn >= torch.iinfo(torch.int8).min:
            return x.to(torch.int8)
        if mx <= torch.iinfo(torch.int16).max and mn >= torch.iinfo(torch.int16).min:
            return x.to(torch.int16)
        if mx <= torch.iinfo(torch.int32).max and mn >= torch.iinfo(torch.int32).min:
            return x.to(torch.int32)
        return x.to(torch.int64)

    if x.dtype in (torch.float64, torch.float32, torch.float16, torch.float):
        mx = nanmax(x)
        mn = nanmin(x)

        if mx <= torch.finfo(torch.float16).max and mn >= torch.finfo(torch.float16).min:
            return x.to(torch.float16)
        if mx <= torch.finfo(torch.float32).max and mn >= torch.finfo(torch.float32).min:
            return x.to(torch.float32)
        return x.to(torch.float64)

    raise ValueError(f"Unexpected dtype: {x.dtype=}")


def check_model_parameters(model: nn.Module, min_: float = -float("inf"), max_: float = float("inf")) -> list[tuple[str, tuple[Literal["nan", "inf", ">", "<"]]]]:
    # For example, check_model_parameters(model, -torch.finfo(torch.float32).max, torch.finfo(torch.float32).max)
    all_issues = []
    for name, param in model.named_parameters():
        param_data = param.data
        issues = []
        if torch.isnan(param_data).any():
            issues.append("NaN")
        if torch.isinf(param_data).any():
            issues.append("Inf")
        if (param_data > max_).any():
            issues.append(f"> {param_data.max().item()}")
        if (param_data < min_).any():
            issues.append(f"< {param_data.min().item()}")
        if issues:
            all_issues.append((name, tuple(issues)))
    return all_issues


def count_parameters(model: nn.Module, requires_grad: bool = False) -> int:
    return sum(p.numel() for p in model.parameters() if (not requires_grad or p.requires_grad))


def detect_anomalous_parameters(model: nn.Module) -> tuple[bool, bool]:
    has_nan = any(torch.isnan(p).any() for p in model.parameters())
    has_inf = any(torch.isinf(p).any() for p in model.parameters())
    return has_nan, has_inf


def detect_anomalous_gradients(model: nn.Module) -> tuple[bool, bool]:
    has_nan = any(p.grad is not None and torch.isnan(p.grad).any() for p in model.parameters())
    has_inf = any(p.grad is not None and torch.isinf(p.grad).any() for p in model.parameters())
    return has_nan, has_inf


def compute_gradient_norm(
    model: nn.Module,
    norm_type: float = 2.0,
    dtype: torch.dtype = None,
) -> float:
    norm = 0
    for p in model.parameters():
        norm += p.grad.data.norm(norm_type, dtype=dtype) ** 2
    norm = norm ** .5
    return norm.detach().cpu().item()


UPCAST_TENSOR = {
    torch.int8: torch.int16,
    torch.int16: torch.int32,
    torch.int32: torch.int64,

    torch.bfloat16: torch.float32,
    torch.float16: torch.float32,
    torch.float32: torch.float64,
}


def basic_tensor_stats(x: Tensor) -> tuple[float, float, float, float]:
    import math

    _mean = x.mean().cpu().item()
    _std = x.std().cpu().item()
    _min = x.min().cpu().item()
    _max = x.max().cpu().item()
    r = (_mean, _std, _min, _max)

    upcast = UPCAST_TENSOR.get(x.dtype, None)

    if upcast is not None and any(math.isnan(v) or math.isinf(v) for v in r):
        return basic_tensor_stats(x.to(upcast))

    return r


def log_tensor(path, x: Tensor, name: str) -> None:
    """
    Log statistics of a tensor to a CSV file for debugging.

    Args:
        path: The path to the directory where the CSV file is stored.
        x: The tensor to log.
        name: The stem of the csv file.

    If the CSV file does not exist, it will be created. If it does exist, it will be appended to.
        The csv file will contain the following fields:
            pos_min: The minimum value of the positive elements of the tensor.
            pos_max: The maximum value of the positive elements of the tensor.
            pos_mean: The mean value of the positive elements of the tensor.
            pos_stdev: The standard deviation of the positive elements of the tensor.
            neg_min: The minimum value of the negative elements of the tensor.
            neg_max: The maximum value of the negative elements of the tensor.
            neg_mean: The mean value of the negative elements of the tensor.
            neg_stdev: The standard deviation of the negative elements of the tensor.
            dtype: The dtype of the tensor.
            shape: The shape of the tensor.
        If the tensor is all zero, each field will be 0.
        If the tensor contains NaN, each field will be NaN.
    """
    from pathlib import Path

    path = Path(path)
    if not path.exists():
        path.mkdir(parents=True)

    p = path / f"{name}.csv"

    if not p.exists():
        with open(p, "w") as fp:
            fp.write("pos_min,pos_max,pos_mean,pos_stdev,neg_min,neg_max,neg_mean,neg_stdev,dtype,shape\n")

    dtype = str(x.dtype)
    shape = "_".join(str(s) for s in x.shape)

    if torch.any(torch.isnan(x)):
        with open(p, "a") as fp:
            fp.write(f"NaN,NaN,NaN,NaN,NaN,NaN,NaN,NaN,{dtype},{shape}\n")
        return

    if torch.all(x == 0):
        with open(p, "a") as fp:
            fp.write(f"0,0,0,0,0,0,0,0,{dtype},{shape}\n")
        return

    pos: Tensor = x[(x > 0) & (x != 0)]
    with open(p, "a") as fp:
        if pos.numel() == 0:
            fp.write(",,,,")
        else:
            fp.write(
                f"{pos.min().item()},"
                f"{pos.max().item()},"
                f"{pos.mean().item()},"
                f"{pos.std().item()},"
            )

    neg: Tensor = x[(x < 0) & (x != 0)]
    with open(p, "a") as fp:
        if neg.numel() == 0:
            fp.write(",,,,")
        else:
            fp.write(
                f"{neg.min().item()},"
                f"{neg.max().item()},"
                f"{neg.mean().item()},"
                f"{neg.std().item()},"
            )

    with open(p, "a") as fp:
        fp.write(f"{dtype},{shape}\n")


def stable_softmax(x: Tensor, dim: int = 0):
    max_values, _ = torch.max(x, dim=dim, keepdim=True)
    exp_scores = torch.exp(x - max_values)
    sum_exp_scores = torch.sum(exp_scores, dim=dim, keepdim=True)
    softmax_result = exp_scores / sum_exp_scores
    return softmax_result


def to_long_tensor(x) -> LongTensor:
    if isinstance(x, bytes):
        return torch.frombuffer(x, dtype=torch.uint8).to(torch.long)
    if isinstance(x, list):
        return torch.tensor(x, dtype=torch.long)
    if isinstance(x, np.ndarray):
        return torch.from_numpy(x.astype(np.int64)).to(torch.long)
    if isinstance(x, Tensor):
        return x.to(torch.long)
    raise TypeError(f"Unexpected type: {type(x)=}")


def get_array_datatype(x) -> Literal["int", "float"]:

    def datatype_of_list(x: list) -> Literal["int", "float"]:
        if isinstance(x[0], list):
            return datatype_of_list(x[0])
        return type(x[0]).__name__

    if isinstance(x, Tensor):
        return str(x.dtype).split(".")[1][:-2]
    if isinstance(x, np.ndarray):
        return str(x.dtype)[:-2]
    if isinstance(x, list):
        return datatype_of_list(x)
    if isinstance(x, (int, float)):
        return type(x).__name__

    raise ValueError(f"Unexpected type: {type(x)=}")


def get_array_shape(x) -> tuple[int]:

    def shape_of_list(x: list) -> tuple[int]:
        if isinstance(x[0], list):
            return (len(x),) + shape_of_list(x[0])
        return (len(x),)

    if isinstance(x, Tensor):
        return tuple(x.shape)
    if isinstance(x, np.ndarray):
        return tuple(x.shape)
    if isinstance(x, list):
        return shape_of_list(x)
    if isinstance(x, (int, float)):
        return tuple()

    raise ValueError(f"Unexpected type: {type(x)=}")


def get_array_dim(x) -> int:
    return len(get_array_shape(x))
