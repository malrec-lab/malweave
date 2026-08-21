"""Low-level file/archive reading and writing helpers, independent of malware-specific logic."""

from .archives import get_data_from_archives, get_processed_data
from .binary_files import (
    read_binary_file,
    read_binary_files,
    read_binary_files_lazy,
    read_binary_file_asynch,
    read_binary_files_asynch,
    read_binary_files_asynch_lazy,
    write_binary_file,
    write_binary_file_asynch,
    write_binary_files_asynch,
)
from .decompression import Decompressor, decompress_error_resilient, decompress_collection

__all__ = [
    "get_data_from_archives",
    "get_processed_data",
    "read_binary_file",
    "read_binary_files",
    "read_binary_files_lazy",
    "read_binary_file_asynch",
    "read_binary_files_asynch",
    "read_binary_files_asynch_lazy",
    "write_binary_file",
    "write_binary_file_asynch",
    "write_binary_files_asynch",
    "Decompressor",
    "decompress_error_resilient",
    "decompress_collection",
]
