"""
evaluator.py
Cryptographic evaluation module for TEA, MTEA, and XTEA.
Contains code to verify equivalent keys, analyze avalanche effect,
test key sensitivity, and run performance benchmarks.
"""

import time
import random
from typing import Callable, Tuple, List, Dict

# Helper: Count set bits in an integer
def popcount(x: int) -> int:
    """Count the number of 1-bits in a 32-bit unsigned integer."""
    return bin(x & 0xFFFFFFFF).count('1')


# Helper: Count differing bits between two 64-bit blocks
def count_diff_bits(block1: Tuple[int, int], block2: Tuple[int, int]) -> int:
    """Return the number of differing bits between two 64-bit blocks."""
    diff0 = block1[0] ^ block2[0]
    diff1 = block1[1] ^ block2[1]
    return popcount(diff0) + popcount(diff1)


# Helper: Flip a bit in a 64-bit block (0-indexed, 0 to 63)
def flip_bit_64(block: Tuple[int, int], bit_pos: int) -> Tuple[int, int]:
    """Flip the specified bit in a 64-bit block."""
    v0, v1 = block
    if bit_pos < 32:
        return (v0 ^ (1 << bit_pos), v1)
    else:
        return (v0, v1 ^ (1 << (bit_pos - 32)))


# Helper: Flip a bit in a 128-bit key (0-indexed, 0 to 127)
def flip_bit_128(key: List[int], bit_pos: int) -> List[int] :
    """Flip the specified bit in a 128-bit key."""
    key_new = list(key)
    word_idx = bit_pos // 32
    bit_idx = bit_pos % 32
    key_new[word_idx] ^= (1 << bit_idx)
    return key_new


# =====================================================================
# 1. Equivalent Key Finder
# =====================================================================

def verify_equivalent_keys(encrypt_fn: Callable[[Tuple[int, int], List[int], int], Tuple[int, int]], 
                            num_test_keys: int = 10) -> List[Tuple[int, int, int, int]]:
    """
    Checks all 15 non-zero MSB-flip combinations of the key.
    For each combination delta_K, we check if it always produces identical ciphertexts
    across multiple random test keys and plaintexts.
    
    A combination delta_K = (d0, d1, d2, d3) where di in {0, 2**31}.
    Returns a list of equivalent key differences (as tuples of 32-bit integers) that always hold.
    """
    equivalent_diffs = []
    
    # Generate the 15 possible non-zero combinations of MSB flips
    # (bit 31 is 1 << 31 = 0x80000000)
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
        
        # Test across multiple random keys and plaintexts
        for _ in range(num_test_keys):
            # Generate random 128-bit key
            key = [random.randint(0, 0xFFFFFFFF) for _ in range(4)]
            # Generate random 64-bit plaintext
            pt = (random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))
            
            # Encrypt under key K
            ct1 = encrypt_fn(pt, key, 32)
            
            # Encrypt under key K' = K ^ diff
            key_equiv = [
                key[0] ^ d0,
                key[1] ^ d1,
                key[2] ^ d2,
                key[3] ^ d3
            ]
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

def run_avalanche_simulation(encrypt_fn: Callable[[Tuple[int, int], List[int], int], Tuple[int, int]], 
                              num_samples: int = 100, 
                              max_cycles: int = 32) -> List[float]:
    """
    Measures the avalanche effect for cycles from 1 to max_cycles.
    Returns a list of average bit-change percentages for each cycle.
    
    For each sample:
    - We generate a random plaintext P and a random key K.
    - For each of the 64 bit positions in the plaintext, we flip that bit to get P_flipped.
    - We encrypt both P and P_flipped under key K for c cycles.
    - We count the number of differing bits in the resulting ciphertexts.
    - We average this count over all samples and bit positions, then convert to a percentage.
    """
    # Results will hold the average percentage for each cycle from 1 to max_cycles
    results = [0.0] * max_cycles
    
    # Generate random test cases
    samples = []
    for _ in range(num_samples):
        key = [random.randint(0, 0xFFFFFFFF) for _ in range(4)]
        pt = (random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))
        samples.append((pt, key))
        
    for cycle in range(1, max_cycles + 1):
        total_bit_changes = 0
        total_tests = 0
        
        for pt, key in samples:
            # Ciphertext for original plaintext
            ct_orig = encrypt_fn(pt, key, cycle)
            
            # Flip each bit of the plaintext
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

def run_key_sensitivity_simulation(encrypt_fn: Callable[[Tuple[int, int], List[int], int], Tuple[int, int]], 
                                    num_samples: int = 100, 
                                    max_cycles: int = 32) -> List[float]:
    """
    Measures the key sensitivity for cycles from 1 to max_cycles.
    Returns a list of average bit-change percentages for each cycle.
    
    For each sample:
    - We generate a random plaintext P and a random key K.
    - For each of the 128 bit positions in the key, we flip that bit to get K_flipped.
    - We encrypt plaintext P under both K and K_flipped for c cycles.
    - We count the number of differing bits in the resulting ciphertexts.
    - We average this count over all samples and key bit positions, then convert to a percentage.
    """
    results = [0.0] * max_cycles
    
    # Generate random test cases
    samples = []
    for _ in range(num_samples):
        key = [random.randint(0, 0xFFFFFFFF) for _ in range(4)]
        pt = (random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))
        samples.append((pt, key))
        
    for cycle in range(1, max_cycles + 1):
        total_bit_changes = 0
        total_tests = 0
        
        for pt, key in samples:
            # Ciphertext for original key
            ct_orig = encrypt_fn(pt, key, cycle)
            
            # Flip each bit of the key (we select a subset of 32 bits to speed up the simulation if needed,
            # but 128 is feasible for python CLI execution with num_samples=100)
            # To be thorough, we test all 128 bits of the key
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

def benchmark_cipher(encrypt_fn: Callable[[Tuple[int, int], List[int], int], Tuple[int, int]], 
                     num_blocks: int = 20000, 
                     cycles: int = 32) -> float:
    """
    Measures the time taken (in seconds) to encrypt a given number of 64-bit blocks
    under a fixed random key.
    """
    key = [random.randint(0, 0xFFFFFFFF) for _ in range(4)]
    # Pre-generate blocks to avoid measuring random number generation time
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
        "XTEA": xtea_encrypt
    }
    
    print("=" * 60)
    print("CRYPTOGRAPHIC EVALUATION OF TEA, MTEA, AND XTEA")
    print("=" * 60)
    
    # 1. Equivalent Key Finder
    print("\n1. Equivalent Key Verification")
    print("-" * 30)
    for name, encrypt_fn in ciphers.items():
        print(f"Checking {name}...")
        equivs = verify_equivalent_keys(encrypt_fn, num_test_keys=20)
        if equivs:
            print(f"  -> Found {len(equivs)} equivalent key differences:")
            for eq in equivs:
                # Format difference in hex for clarity
                hex_diffs = [f"0x{d:08X}" for d in eq]
                print(f"     {hex_diffs}")
        else:
            print("  -> No equivalent keys found.")
            
    # 2. Avalanche Effect Simulation
    print("\n2. Avalanche Effect (Plaintext Bit Flipping)")
    print("-" * 50)
    # We can print at cycles 1, 8, 16, 24, 32
    sample_cycles = [1, 8, 16, 24, 32]
    for name, encrypt_fn in ciphers.items():
        print(f"{name}:")
        results = run_avalanche_simulation(encrypt_fn, num_samples=100, max_cycles=32)
        for c in sample_cycles:
            if c <= len(results):
                print(f"  Cycle {c:2d}: {results[c-1]:.2f}% of ciphertext bits changed")
                
    # 3. Key Sensitivity Simulation
    print("\n3. Key Sensitivity (Key Bit Flipping)")
    print("-" * 50)
    for name, encrypt_fn in ciphers.items():
        print(f"{name}:")
        results = run_key_sensitivity_simulation(encrypt_fn, num_samples=100, max_cycles=32)
        for c in sample_cycles:
            if c <= len(results):
                print(f"  Cycle {c:2d}: {results[c-1]:.2f}% of ciphertext bits changed")
                
    # 4. Performance Benchmarking
    print("\n4. Performance Benchmark (Encrypting 50,000 blocks with 32 cycles)")
    print("-" * 60)
    for name, encrypt_fn in ciphers.items():
        t = benchmark_cipher(encrypt_fn, num_blocks=50000, cycles=32)
        throughput = (50000 * 8) / (t * 1024) # KB/s
        print(f"{name:16s}: {t:.4f} seconds ({throughput:.2f} KB/s)")
    print("=" * 60)
