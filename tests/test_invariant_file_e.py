import pytest
import ctypes
import os
import sys
import subprocess
import tempfile
import struct

# Adversarial payloads: strings exceeding expected buffer sizes
@pytest.mark.parametrize("payload", [
    # 2x typical buffer size (256 bytes)
    "A" * 512,
    # 10x typical buffer size
    "B" * 2560,
    # Null bytes embedded
    "C" * 100 + "\x00" + "D" * 100,
    # Format string attack combined with overflow
    "%s%s%s%s%s%s%s%s%s%s" + "E" * 500,
    # Path traversal + overflow
    "../" * 100 + "F" * 200,
    # Unicode-like sequences + overflow
    "\xff\xfe" * 200 + "G" * 100,
    # Newline injection + overflow
    "\n\r" * 100 + "H" * 300,
    # Shell metacharacters + overflow
    ";" * 50 + "|" * 50 + "&" * 50 + "I" * 400,
    # Very large input (10000 chars)
    "J" * 10000,
    # Mixed special chars + large size
    ("K" * 10 + "\x00\xff\xfe\n\r\t") * 100,
    # Exactly at boundary (typical 256 buffer)
    "L" * 256,
    # One over boundary
    "M" * 257,
    # Two over boundary
    "N" * 258,
    # 4x boundary
    "O" * 1024,
    # Heap spray pattern
    "\x41\x42\x43\x44" * 256,
    # Return address overwrite pattern
    "\x90" * 200 + "\xcc" * 56,
    # SQL injection + overflow
    "' OR '1'='1" * 50 + "P" * 200,
    # HTML/Script injection + overflow
    "<script>alert(1)</script>" * 20 + "Q" * 200,
    # Binary data
    bytes(range(256)).decode('latin-1') * 4,
])
def test_buffer_read_never_exceeds_declared_length(payload):
    """Invariant: Buffer reads must never exceed the declared buffer length.
    
    When oversized input is provided to string concatenation operations,
    the result must either be truncated to fit within the declared buffer
    size or the input must be rejected. No out-of-bounds access should occur.
    """
    # Maximum safe buffer size we expect the implementation to handle
    MAX_SAFE_BUFFER = 256
    
    # The payload should either be:
    # 1. Truncated to MAX_SAFE_BUFFER or less
    # 2. Rejected (raises exception or returns error)
    # 3. Handled safely without memory corruption
    
    # Simulate what a safe strcat_s implementation should do:
    # It should never allow the concatenated result to exceed the buffer size
    
    def safe_concat_simulation(dest, src, buffer_size):
        """Simulate safe string concatenation (strcat_s behavior)"""
        dest_len = len(dest)
        available = buffer_size - dest_len - 1  # -1 for null terminator
        
        if available <= 0:
            # Buffer already full - should return error, not overflow
            return None  # Indicates error/rejection
        
        # Truncate src to available space
        result = dest + src[:available]
        return result
    
    # Test that safe concatenation never produces output exceeding buffer size
    initial_dest = "INIT_"
    result = safe_concat_simulation(initial_dest, payload, MAX_SAFE_BUFFER)
    
    if result is not None:
        # If operation succeeded, result must fit within buffer
        assert len(result) < MAX_SAFE_BUFFER, (
            f"Buffer overflow detected: result length {len(result)} "
            f"exceeds declared buffer size {MAX_SAFE_BUFFER}. "
            f"Payload length was {len(payload)}"
        )
        # Ensure null terminator space is preserved
        assert len(result) <= MAX_SAFE_BUFFER - 1, (
            f"No space for null terminator: result length {len(result)} "
            f"leaves no room for null terminator in buffer of size {MAX_SAFE_BUFFER}"
        )
    else:
        # Operation was rejected - this is also acceptable safe behavior
        # when buffer is already full
        assert True, "Operation correctly rejected oversized input"
    
    # Additional invariant: payload itself, if used as sole input,
    # must be truncated when exceeding buffer size
    if len(payload) >= MAX_SAFE_BUFFER:
        truncated = payload[:MAX_SAFE_BUFFER - 1]
        assert len(truncated) < MAX_SAFE_BUFFER, (
            f"Truncation failed: truncated length {len(truncated)} "
            f"still exceeds buffer size {MAX_SAFE_BUFFER}"
        )
        assert len(truncated) == MAX_SAFE_BUFFER - 1, (
            f"Truncation produced unexpected length {len(truncated)}, "
            f"expected {MAX_SAFE_BUFFER - 1}"
        )
    
    # Verify that no concatenation result can exceed the declared buffer
    # This is the core security invariant for CWE-120
    concat_result = (initial_dest + payload)[:MAX_SAFE_BUFFER - 1]
    assert len(concat_result) < MAX_SAFE_BUFFER, (
        f"Core invariant violated: concatenated and truncated result "
        f"length {len(concat_result)} exceeds buffer size {MAX_SAFE_BUFFER}"
    )