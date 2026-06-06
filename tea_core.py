"""
tea_core.py
Core implementations of the Tiny Encryption Algorithm (TEA)
and the proposed Modified Tiny Encryption Algorithm (MTEA) with dynamic key schedule.
"""

from typing import Tuple, List
import struct


# Bitwise left rotation for a 32-bit unsigned integer
def rotl(x: int, n: int) -> int:
    """Left rotate 32-bit integer x by n positions."""
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# =====================================================================
# Plaintext <-> Block Utilities
# =====================================================================

def text_to_blocks(text: str) -> List[Tuple[int, int]]:
    """
    Convert a UTF-8 string to a list of 64-bit blocks (v0, v1).
    Pads with zeros to a multiple of 8 bytes.
    """
    data = text.encode('utf-8')
    # Pad to multiple of 8 bytes
    pad_len = (8 - len(data) % 8) % 8
    data += b'\x00' * pad_len
    blocks = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        v0, v1 = struct.unpack('>II', chunk)
        blocks.append((v0, v1))
    return blocks


def blocks_to_text(blocks: List[Tuple[int, int]]) -> str:
    """
    Convert a list of 64-bit blocks (v0, v1) back to a UTF-8 string.
    Strips null-byte padding.
    """
    data = b''
    for v0, v1 in blocks:
        data += struct.pack('>II', v0, v1)
    return data.rstrip(b'\x00').decode('utf-8', errors='replace')


def blocks_to_hex(blocks: List[Tuple[int, int]]) -> str:
    """Convert a list of blocks to a readable hex string."""
    return ' '.join(f'{v0:08X}{v1:08X}' for v0, v1 in blocks)


def key_from_string(key_str: str) -> List[int]:
    """
    Derive a 128-bit key (4 x 32-bit words) from a string.
    Pads or truncates to exactly 16 bytes.
    """
    key_bytes = key_str.encode('utf-8')
    key_bytes = (key_bytes + b'\x00' * 16)[:16]
    return list(struct.unpack('>IIII', key_bytes))


# =====================================================================
# 1. Original Tiny Encryption Algorithm (TEA)
# =====================================================================

def tea_encrypt(v: Tuple[int, int], k: List[int], cycles: int = 32) -> Tuple[int, int]:
    """Encrypt a 64-bit block v = (v0, v1) using 128-bit key k with TEA."""
    v0, v1 = v
    k0, k1, k2, k3 = k
    sum_val = 0
    delta = 0x9E3779B9

    for _ in range(cycles):
        sum_val = (sum_val + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF

    return (v0, v1)


def tea_decrypt(v: Tuple[int, int], k: List[int], cycles: int = 32) -> Tuple[int, int]:
    """Decrypt a 64-bit block v = (v0, v1) using 128-bit key k with TEA."""
    v0, v1 = v
    k0, k1, k2, k3 = k
    delta = 0x9E3779B9
    sum_val = (delta * cycles) & 0xFFFFFFFF

    for _ in range(cycles):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF

    return (v0, v1)


# =====================================================================
# 2. Proposed Modified Tiny Encryption Algorithm (MTEA)
# =====================================================================

def mtea_encrypt(v: Tuple[int, int], k: List[int], cycles: int = 32) -> Tuple[int, int]:
    """
    Encrypt a 64-bit block v = (v0, v1) using 128-bit key k with MTEA.
    Improvement: dynamic round-dependent key schedule using sum-dependent rotations,
    which eliminates TEA's equivalent key vulnerability.
    """
    v0, v1 = v
    k0_static, k1_static, k2_static, k3_static = k
    sum_val = 0
    delta = 0x9E3779B9

    for _ in range(cycles):
        sum_val = (sum_val + delta) & 0xFFFFFFFF

        # Dynamic round keys: rotation amount changes every round based on sum
        k0 = rotl(k0_static, sum_val & 31)
        k1 = rotl(k1_static, (sum_val >> 5) & 31)
        k2 = rotl(k2_static, (sum_val >> 10) & 31)
        k3 = rotl(k3_static, (sum_val >> 15) & 31)

        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF

    return (v0, v1)


def mtea_decrypt(v: Tuple[int, int], k: List[int], cycles: int = 32) -> Tuple[int, int]:
    """Decrypt a 64-bit block v = (v0, v1) using 128-bit key k with MTEA."""
    v0, v1 = v
    k0_static, k1_static, k2_static, k3_static = k
    delta = 0x9E3779B9
    sum_val = (delta * cycles) & 0xFFFFFFFF

    for _ in range(cycles):
        k0 = rotl(k0_static, sum_val & 31)
        k1 = rotl(k1_static, (sum_val >> 5) & 31)
        k2 = rotl(k2_static, (sum_val >> 10) & 31)
        k3 = rotl(k3_static, (sum_val >> 15) & 31)

        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF

    return (v0, v1)


# =====================================================================
# High-Level Encrypt/Decrypt for Full Plaintext Strings
# =====================================================================

def encrypt_text(plaintext: str, key_str: str, cipher: str = 'mtea', cycles: int = 32) -> str:
    """
    Encrypt a plaintext string using the chosen cipher.
    Returns the ciphertext as a hex string.
    cipher: 'tea' or 'mtea'
    """
    key = key_from_string(key_str)
    blocks = text_to_blocks(plaintext)

    fn_map = {'tea': tea_encrypt, 'mtea': mtea_encrypt}
    encrypt_fn = fn_map[cipher.lower()]

    enc_blocks = [encrypt_fn(b, key, cycles) for b in blocks]
    return blocks_to_hex(enc_blocks)


def decrypt_text(hex_ciphertext: str, key_str: str, cipher: str = 'mtea', cycles: int = 32) -> str:
    """
    Decrypt a hex ciphertext string using the chosen cipher.
    Returns the recovered plaintext string.
    cipher: 'tea' or 'mtea'
    """
    key = key_from_string(key_str)
    # Parse hex string back into blocks
    hex_ciphertext = hex_ciphertext.replace(' ', '')
    blocks = []
    for i in range(0, len(hex_ciphertext), 16):
        chunk = hex_ciphertext[i:i+16]
        v0 = int(chunk[:8], 16)
        v1 = int(chunk[8:16], 16)
        blocks.append((v0, v1))

    fn_map = {'tea': tea_decrypt, 'mtea': mtea_decrypt}
    decrypt_fn = fn_map[cipher.lower()]

    dec_blocks = [decrypt_fn(b, key, cycles) for b in blocks]
    return blocks_to_text(dec_blocks)
