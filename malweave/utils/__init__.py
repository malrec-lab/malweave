"""
Small shared utilities with no model or dataset-specific behavior.

Split by domain into separate modules (tensor, system, fs, iterables, context,
concurrency, codec, debug) for readability. Everything is re-exported here so
callers only need:

    from malweave.utils import seed_everything, batched, rglob

instead of reaching into the specific submodule.
"""

from .tensor import (
    seed_everything,
    nanmax,
    nanmin,
    torch_safe_downcast,
    check_model_parameters,
    count_parameters,
    detect_anomalous_parameters,
    detect_anomalous_gradients,
    compute_gradient_norm,
    UPCAST_TENSOR,
    basic_tensor_stats,
    log_tensor,
    stable_softmax,
    to_long_tensor,
    get_array_datatype,
    get_array_shape,
    get_array_dim,
)
from .system import (
    process_mem,
    gig,
    mem,
    print_gpu_utilization,
    print_summary,
    get_memory_usage,
)
from .fs import (
    rglob,
    maybe_temp_file,
    get_unique_files,
    count_lines_big_file,
    output_root,
    remove_empty_directories,
    get_paths_sorted_numerically,
    get_highest_path,
    is_dataset_path,
    is_dataset_path_completed,
)
from .iterables import (
    unique_value,
    getattr_recursively,
    batched,
    get_scale_fn,
    object_from_superset_of_constructor_kwds,
    compose_functions,
    get_max_keys_from_dict,
    is_jsonable,
    flatten,
)
from .context import (
    print_context,
    ignore_warnings_decorator,
)
from .concurrency import (
    process_files_asynch,
)
from .codec import (
    CompressionAlgorithm,
    EncryptionAlgorithm,
    compress,
    encrypt,
)
from .debug import (
    bash_file_to_vscode_debug_str,
)

__all__ = [
    # tensor
    "seed_everything",
    "nanmax",
    "nanmin",
    "torch_safe_downcast",
    "check_model_parameters",
    "count_parameters",
    "detect_anomalous_parameters",
    "detect_anomalous_gradients",
    "compute_gradient_norm",
    "UPCAST_TENSOR",
    "basic_tensor_stats",
    "log_tensor",
    "stable_softmax",
    "to_long_tensor",
    "get_array_datatype",
    "get_array_shape",
    "get_array_dim",
    # system
    "process_mem",
    "gig",
    "mem",
    "print_gpu_utilization",
    "print_summary",
    "get_memory_usage",
    # fs
    "rglob",
    "maybe_temp_file",
    "get_unique_files",
    "count_lines_big_file",
    "output_root",
    "remove_empty_directories",
    "get_paths_sorted_numerically",
    "get_highest_path",
    "is_dataset_path",
    "is_dataset_path_completed",
    # iterables
    "unique_value",
    "getattr_recursively",
    "batched",
    "get_scale_fn",
    "object_from_superset_of_constructor_kwds",
    "compose_functions",
    "get_max_keys_from_dict",
    "is_jsonable",
    "flatten",
    # context
    "print_context",
    "ignore_warnings_decorator",
    # concurrency
    "process_files_asynch",
    # codec
    "CompressionAlgorithm",
    "EncryptionAlgorithm",
    "compress",
    "encrypt",
    # debug
    "bash_file_to_vscode_debug_str",
]
