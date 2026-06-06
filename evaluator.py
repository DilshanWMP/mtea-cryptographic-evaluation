"""
evaluator.py
Cryptographic evaluation module for TEA, MTEA, and XTEA.
Contains code to verify equivalent keys, analyze avalanche effect,
test key sensitivity, and run performance benchmarks.
"""

import time
import random
from typing import Callable, Tuple, List


# Helper: Count set bits in an integer
def popcount(x: int) -> int:
    """Count the number of 1-bits in a 32-bit unsigned integer."""
    return bin(x & 0xFFFFFFFF).count('1')


# Helper: Count differing bits between two 64-bit blocks
def count_diff_bits(block1: Tuple[int, int], block2: Tuple[int, int]) -> int:
    diff0 = block1[0] ^ block2[0]
    diff1 = block1[1] ^ block2[1]
    return popcount(diff0) + popcount(diff1)


# Helper: Flip a bit in a 64-bit block (0-indexed, 0 to 63)
def flip_bit_64(block: Tuple[int, int], bit_pos: int) -> Tuple[int, int]:
    v0, v1 = block
    if bit_pos < 32:
        return (v0 ^ (1 << bit_pos), v1)
    else:
        return (v0, v1 ^ (1 << (bit_pos - 32)))


# Helper: Flip a bit in a 128-bit key (0-indexed, 0 to 127)
def flip_bit_128(key: List[int], bit_pos: int) -> List[int]:
    key_new = list(key)
    word_idx = bit_pos // 32
    bit_idx = bit_pos % 32
    key_new[word_idx] ^= (1 << bit_idx)
    return key_new


# =====================================================================
# 1. Equivalent Key Finder
# =====================================================================

def verify_equivalent_keys(encrypt_fn, num_test_keys: int = 10) -> List[Tuple[int, int, int, int]]:
    """
    Checks all 15 non-zero MSB-flip combinations of the key.
    Returns a list of equivalent key differences that always produce
    identical ciphertexts (i.e., true equivalent keys).
    TEA is known to have 4 equivalent keys per key due to its static key schedule.
    MTEA's dynamic schedule is designed to eliminate this.
    """
    equivalent_diffs = []
    msb = 0x80000000
    combinations = []
    for i in range(1, 16):
        d0 = msb if (i & 1) else 0
        d1 = msb if (i & 2) else 0
        d2 = msb if (i & 4) else 0
        d3 = msb if (i & 8) else 0
        combinations.append((d0, d1, d2, d3))

    for diff in combinations:
        d0, d1, d2, d3 = diff
        is_equivalent = True

        for _ in range(num_test_keys):
            key = [random.randint(0, 0xFFFFFFFF) for _ in range(4)]
            pt = (random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))

            ct1 = encrypt_fn(pt, key, 32)
            key_equiv = [key[0] ^ d0, key[1] ^ d1, key[2] ^ d2, key[3] ^ d3]
            ct2 = encrypt_fn(pt, key_equiv, 32)

            if ct1 != ct2:
                is_equivalent = False
                break

        if is_equivalent:
            equivalent_diffs.append(diff)

    return equivalent_diffs


# =====================================================================
# 2. Avalanche Effect Simulation
# =====================================================================

def run_avalanche_simulation(encrypt_fn, num_samples: int = 100, max_cycles: int = 32) -> List[float]:
    """
    Measures the avalanche effect by flipping each of the 64 plaintext bits
    and measuring how many ciphertext bits change.
    Ideal: ~50% (32 out of 64 bits) change with each single bit flip.
    """
    results = [0.0] * max_cycles
    samples = []
    for _ in range(num_samples):
        key = [random.randint(0, 0xFFFFFFFF) for _ in range(4)]
        pt = (random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))
        samples.append((pt, key))

    for cycle in range(1, max_cycles + 1):
        total_bit_changes = 0
        total_tests = 0

        for pt, key in samples:
            ct_orig = encrypt_fn(pt, key, cycle)
            for bit_pos in range(64):
                pt_flipped = flip_bit_64(pt, bit_pos)
                ct_flipped = encrypt_fn(pt_flipped, key, cycle)
                total_bit_changes += count_diff_bits(ct_orig, ct_flipped)
                total_tests += 1

        avg_changed_bits = total_bit_changes / total_tests
        percentage = (avg_changed_bits / 64.0) * 100.0
        results[cycle - 1] = percentage

    return results


# =====================================================================
# 3. Key Sensitivity Simulation
# =====================================================================

def run_key_sensitivity_simulation(encrypt_fn, num_samples: int = 100, max_cycles: int = 32) -> List[float]:
    """
    Measures key sensitivity by flipping each of the 128 key bits
    and measuring how many ciphertext bits change.
    Ideal: ~50% change with a single key bit flip.
    """
    results = [0.0] * max_cycles
    samples = []
    for _ in range(num_samples):
        key = [random.randint(0, 0xFFFFFFFF) for _ in range(4)]
        pt = (random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))
        samples.append((pt, key))

    for cycle in range(1, max_cycles + 1):
        total_bit_changes = 0
        total_tests = 0

        for pt, key in samples:
            ct_orig = encrypt_fn(pt, key, cycle)
            for bit_pos in range(128):
                key_flipped = flip_bit_128(key, bit_pos)
                ct_flipped = encrypt_fn(pt, key_flipped, cycle)
                total_bit_changes += count_diff_bits(ct_orig, ct_flipped)
                total_tests += 1

        avg_changed_bits = total_bit_changes / total_tests
        percentage = (avg_changed_bits / 64.0) * 100.0
        results[cycle - 1] = percentage

    return results


# =====================================================================
# 4. Performance Benchmarking
# =====================================================================

def benchmark_cipher(encrypt_fn, num_blocks: int = 20000, cycles: int = 32) -> float:
    """Measures time in seconds to encrypt num_blocks 64-bit blocks."""
    key = [random.randint(0, 0xFFFFFFFF) for _ in range(4)]
    blocks = [(random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF)) for _ in range(num_blocks)]

    start_time = time.perf_counter()
    for block in blocks:
        _ = encrypt_fn(block, key, cycles)
    end_time = time.perf_counter()

    return end_time - start_time


if __name__ == "__main__":
    from tea_core import tea_encrypt, mtea_encrypt, xtea_encrypt

    ciphers = {
        "TEA": tea_encrypt,
        "MTEA (Proposed)": mtea_encrypt,
        "XTEA": xtea_encrypt,
    }

    print("=" * 60)
    print("CRYPTOGRAPHIC EVALUATION: TEA vs MTEA vs XTEA")
    print("=" * 60)

    # 1. Equivalent Key Finder
    print("\n1. Equivalent Key Verification")
    print("   (TEA is known to have 4 equivalent keys per key)")
    print("-" * 50)
    for name, encrypt_fn in ciphers.items():
        print(f"Checking {name}...")
        equivs = verify_equivalent_keys(encrypt_fn, num_test_keys=20)
        if equivs:
            print(f"  -> {len(equivs)} equivalent key difference(s) found [VULNERABLE]:")
            for eq in equivs:
                print(f"     {[f'0x{d:08X}' for d in eq]}")
        else:
            print("  -> No equivalent keys found. [SECURE]")

    # 2. Avalanche Effect
    print("\n2. Avalanche Effect (Plaintext Bit Flipping)")
    print("   (Ideal: ~50% of ciphertext bits change)")
    print("-" * 50)
    sample_cycles = [1, 8, 16, 24, 32]
    for name, encrypt_fn in ciphers.items():
        print(f"{name}:")
        results = run_avalanche_simulation(encrypt_fn, num_samples=100, max_cycles=32)
        for c in sample_cycles:
            bar = '█' * int(results[c - 1] / 2)
            print(f"  Cycle {c:2d}: {results[c-1]:5.2f}%  {bar}")

    # 3. Key Sensitivity
    print("\n3. Key Sensitivity (Key Bit Flipping)")
    print("   (Ideal: ~50% of ciphertext bits change)")
    print("-" * 50)
    for name, encrypt_fn in ciphers.items():
        print(f"{name}:")
        results = run_key_sensitivity_simulation(encrypt_fn, num_samples=100, max_cycles=32)
        for c in sample_cycles:
            bar = '█' * int(results[c - 1] / 2)
            print(f"  Cycle {c:2d}: {results[c-1]:5.2f}%  {bar}")

    # 4. Performance
    print("\n4. Performance Benchmark (50,000 blocks, 32 cycles)")
    print("-" * 50)
    for name, encrypt_fn in ciphers.items():
        t = benchmark_cipher(encrypt_fn, num_blocks=50000, cycles=32)
        throughput = (50000 * 8) / (t * 1024)
        print(f"  {name:20s}: {t:.4f}s  ({throughput:.2f} KB/s)")

    print("\n" + "=" * 60)
