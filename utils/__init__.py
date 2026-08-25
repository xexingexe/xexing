# utils/__init__.py — 通用工具包
from .helpers import (
    format_size, format_duration,
    calc_entropy, calc_entropy_file, entropy_level,
    compute_hashes, compute_hashes_file,
    detect_file_type, detect_file_type_file,
    extract_strings, extract_strings_file,
    create_temp_dir, clean_directory,
    is_pe_file, is_pe_file_path, get_pe_architecture,
    safe_read_file,
)

__all__ = [
    'format_size', 'format_duration',
    'calc_entropy', 'calc_entropy_file', 'entropy_level',
    'compute_hashes', 'compute_hashes_file',
    'detect_file_type', 'detect_file_type_file',
    'extract_strings', 'extract_strings_file',
    'create_temp_dir', 'clean_directory',
    'is_pe_file', 'is_pe_file_path', 'get_pe_architecture',
    'safe_read_file',
]
