"""
tea_core.py
Core implementations of the Tiny Encryption Algorithm (TEA),
the proposed Modified Tiny Encryption Algorithm (MTEA) with dynamic key schedule,
and the Extended Tiny Encryption Algorithm (XTEA).
"""

from typing import Tuple, List

# Bitwise left rotation for a 32-bit unsigned integer
def rotl(x: int, n: int) -> int:
    """Left rotate 32-bit integer x by n positions."""
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# =====================================================================
# 1. Original Tiny Encryption Algorithm (TEA)
# =====================================================================

def tea_encrypt(v: Tuple[int, int], k: List[int], cycles: int = 32) -> Tuple[int, int]:
    """
    Encrypt a 64-bit block v = (v0, v1) using a 128-bit key k = [k0, k1, k2, k3] with TEA.
    """
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
    """
    Decrypt a 64-bit block v = (v0, v1) using a 128-bit key k = [k0, k1, k2, k3] with TEA.
    """
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
    Encrypt a 64-bit block v = (v0, v1) using a 128-bit key k = [k0, k1, k2, k3] with MTEA.
    Introduces a lightweight, dynamic, round-dependent key schedule.
    """
    v0, v1 = v
    k0_static, k1_static, k2_static, k3_static = k
    sum_val = 0
    delta = 0x9E3779B9
    
    for _ in range(cycles):
        sum_val = (sum_val + delta) & 0xFFFFFFFF
        
        # Dynamic round keys using sum-dependent bitwise rotation
        k0 = rotl(k0_static, sum_val & 31)
        k1 = rotl(k1_static, (sum_val >> 5) & 31)
        k2 = rotl(k2_static, (sum_val >> 10) & 31)
        k3 = rotl(k3_static, (sum_val >> 15) & 31)
        
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        
    return (v0, v1)


def mtea_decrypt(v: Tuple[int, int], k: List[int], cycles: int = 32) -> Tuple[int, int]:
    """
    Decrypt a 64-bit block v = (v0, v1) using a 128-bit key k = [k0, k1, k2, k3] with MTEA.
    """
    v0, v1 = v
    k0_static, k1_static, k2_static, k3_static = k
    delta = 0x9E3779B9
    sum_val = (delta * cycles) & 0xFFFFFFFF
    
    for _ in range(cycles):
        # Dynamic round keys generated using sum-dependent bitwise rotation
        k0 = rotl(k0_static, sum_val & 31)
        k1 = rotl(k1_static, (sum_val >> 5) & 31)
        k2 = rotl(k2_static, (sum_val >> 10) & 31)
        k3 = rotl(k3_static, (sum_val >> 15) & 31)
        
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
        
    return (v0, v1)


# =====================================================================
# 3. Extended Tiny Encryption Algorithm (XTEA)
# =====================================================================

def xtea_encrypt(v: Tuple[int, int], k: List[int], cycles: int = 32) -> Tuple[int, int]:
    """
    Encrypt a 64-bit block v = (v0, v1) using a 128-bit key k = [k0, k1, k2, k3] with XTEA.
    Note: 32 cycles correspond to 64 Feistel rounds.
    """
    v0, v1 = v
    sum_val = 0
    delta = 0x9E3779B9
    
    for _ in range(cycles):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + k[sum_val & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val + delta) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + k[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
        
    return (v0, v1)


def xtea_decrypt(v: Tuple[int, int], k: List[int], cycles: int = 32) -> Tuple[int, int]:
    """
    Decrypt a 64-bit block v = (v0, v1) using a 128-bit key k = [k0, k1, k2, k3] with XTEA.
    """
    v0, v1 = v
    delta = 0x9E3779B9
    sum_val = (delta * cycles) & 0xFFFFFFFF
    
    for _ in range(cycles):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + k[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + k[sum_val & 3]))) & 0xFFFFFFFF
        
    return (v0, v1)
