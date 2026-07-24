"""
Immediate operand scanner for .text section bytes.

Scans raw x86 bytes for `push imm32` and `mov reg, imm32` instructions
whose immediate values fall within .rdata (or .data) address ranges.
This captures string/data references that the xref database misses
because it only tracked CS_OP_MEM operands, not CS_OP_IMM.
"""

import struct
from collections import defaultdict

from . import config


def scan_immediate_refs(xbe_data, functions, verbose=False):
    """Scan every approved code section for immediate references to target data."""
    func_starts = sorted(int(function["start"], 16) for function in functions)
    refs_by_data_address = defaultdict(set)
    total_refs = 0

    for section in config.code_sections():
        raw_start = section.raw_address
        raw_size = min(section.raw_size, max(0, len(xbe_data) - raw_start))
        section_bytes = xbe_data[raw_start:raw_start + raw_size]
        if verbose:
            print(
                f"  Scanning {len(section_bytes):,} bytes from {section.name} "
                f"at 0x{section.virtual_address:08X}..."
            )
        index = 0
        end = len(section_bytes) - 5
        while index < end:
            opcode = section_bytes[index]
            immediate = None
            if opcode == 0x68 or 0xB8 <= opcode <= 0xBF:
                immediate = struct.unpack_from("<I", section_bytes, index + 1)[0]
                step = 5
            else:
                step = 1
            if immediate is not None and config.is_data_address(immediate):
                code_va = section.virtual_address + index
                refs_by_data_address[immediate].add(code_va)
                total_refs += 1
            index += step

    if verbose:
        print(f"  Found {total_refs:,} immediate references to approved data sections")
        print(f"  Unique data addresses referenced: {len(refs_by_data_address):,}")

    data_to_funcs = defaultdict(set)
    for data_address, code_addresses in refs_by_data_address.items():
        for code_address in code_addresses:
            function_address = _find_containing_function(code_address, func_starts)
            if function_address is not None:
                data_to_funcs[data_address].add(function_address)

    if verbose:
        mapped = len(set().union(*data_to_funcs.values())) if data_to_funcs else 0
        print(f"  Mapped to {mapped:,} unique functions")
    return {address: sorted(values) for address, values in data_to_funcs.items()}


def _find_containing_function(code_addr, sorted_func_starts):
    """
    Binary search to find which function contains code_addr.
    Returns the function start address, or None if not found.
    """
    lo, hi = 0, len(sorted_func_starts) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if sorted_func_starts[mid] <= code_addr:
            lo = mid + 1
        else:
            hi = mid - 1
    # hi now points to the last func_start <= code_addr
    if hi >= 0:
        return sorted_func_starts[hi]
    return None
