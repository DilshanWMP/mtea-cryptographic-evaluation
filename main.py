"""
main.py
Interactive CLI for demonstrating and evaluating TEA and MTEA.
Takes a plaintext from the user, generates a random 128-bit key, and runs
cryptographic checks showing results directly on the command line.
"""

import os
import sys
import secrets
import string
import time
from typing import Tuple, List, Callable

# Import core cryptographic algorithms
from tea_core import (
    encrypt_text, decrypt_text,
    tea_encrypt, mtea_encrypt,
    text_to_blocks, blocks_to_hex, key_from_string
)

# Enable ANSI escape sequences on Windows terminals
if sys.platform == "win32":
    os.system("")

# Styling Constants
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_CYAN = "\033[1;36m"
COLOR_GREEN = "\033[1;32m"
COLOR_RED = "\033[1;31m"
COLOR_YELLOW = "\033[1;33m"
COLOR_MAGENTA = "\033[1;35m"
COLOR_GRAY = "\033[90m"
COLOR_WHITE = "\033[1;37m"


# Helper: Count set bits in an integer
def popcount(x: int) -> int:
    return bin(x & 0xFFFFFFFF).count('1')

# Helper: Count differing bits between two 64-bit blocks
def count_diff_bits(block1: Tuple[int, int], block2: Tuple[int, int]) -> int:
    return popcount(block1[0] ^ block2[0]) + popcount(block1[1] ^ block2[1])

# Helper: Flip a bit in a 64-bit block (0 to 63)
def flip_bit_64(block: Tuple[int, int], bit_pos: int) -> Tuple[int, int]:
    v0, v1 = block
    if bit_pos < 32:
        return (v0 ^ (1 << bit_pos), v1)
    else:
        return (v0, v1 ^ (1 << (bit_pos - 32)))

# Helper: Flip a bit in a 128-bit key (0 to 127)
def flip_bit_128(key: List[int], bit_pos: int) -> List[int]:
    key_new = list(key)
    word_idx = bit_pos // 32
    bit_idx = bit_pos % 32
    key_new[word_idx] ^= (1 << bit_idx)
    return key_new

def generate_random_key(length: int = 16) -> str:
    """Generate a secure, random alphanumeric string to use as the key."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def print_header(title: str):
    print(f"\n{COLOR_CYAN}{'='*65}{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}  {title}{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'='*65}{COLOR_RESET}")

def run_equivalent_key_check(plaintext: str, key_str: str):
    """Checks equivalent keys specifically using the generated key."""
    print_header("1. EQUIVALENT KEY VERIFICATION")
    print(f"  {COLOR_GRAY}Testing if flipping the MSB (most significant bit) of key words{COLOR_RESET}")
    print(f"  {COLOR_GRAY}produces identical ciphertext (the classic TEA weakness).{COLOR_RESET}\n")

    key = key_from_string(key_str)
    msb = 0x80000000
    # Equivalent key difference for TEA (flipping MSBs)
    key_equiv = [k ^ msb for k in key]

    blocks = text_to_blocks(plaintext)
    ciphers = {
        "TEA": tea_encrypt,
        "MTEA (Proposed)": mtea_encrypt
    }

    for name, encrypt_fn in ciphers.items():
        ct1_blocks = [encrypt_fn(b, key, 32) for b in blocks]
        ct2_blocks = [encrypt_fn(b, key_equiv, 32) for b in blocks]

        ct1 = blocks_to_hex(ct1_blocks)
        ct2 = blocks_to_hex(ct2_blocks)

        same = (ct1 == ct2)
        if same:
            status = f"{COLOR_RED}VULNERABLE{COLOR_RESET} (same ciphertext generated!)"
        else:
            status = f"{COLOR_GREEN}SECURE{COLOR_RESET} (different ciphertext generated)"

        print(f"  {COLOR_BOLD}[{name}]{COLOR_RESET}")
        print(f"    Original Key CT   : {ct1}")
        print(f"    MSB-Flipped Key CT : {ct2}")
        print(f"    Verification       : {status}\n")

def run_avalanche_check(plaintext: str, key_str: str):
    """Runs a live avalanche check on the actual input plaintext."""
    print_header("2. AVALANCHE EFFECT (Diffusion Analysis)")
    print(f"  {COLOR_GRAY}Flipping each bit of the plaintext and measuring how many{COLOR_RESET}")
    print(f"  {COLOR_GRAY}ciphertext bits change. Ideal target: ~50% change.{COLOR_RESET}\n")

    key = key_from_string(key_str)
    blocks = text_to_blocks(plaintext)
    ciphers = {
        "TEA": tea_encrypt,
        "MTEA (Proposed)": mtea_encrypt
    }

    cycles_to_check = [1, 8, 16, 24, 32]

    for name, encrypt_fn in ciphers.items():
        print(f"  {COLOR_BOLD}[{name}]{COLOR_RESET}")
        
        for cycle in cycles_to_check:
            total_bit_changes = 0
            total_tests = 0
            
            for block in blocks:
                ct_orig = encrypt_fn(block, key, cycle)
                # Flip each of the 64 bits in this block
                for bit_pos in range(64):
                    block_flipped = flip_bit_64(block, bit_pos)
                    ct_flipped = encrypt_fn(block_flipped, key, cycle)
                    total_bit_changes += count_diff_bits(ct_orig, ct_flipped)
                    total_tests += 1

            pct = (total_bit_changes / (total_tests * 64)) * 100
            bar_len = int(pct / 2)
            bar = "█" * bar_len
            
            # Highlight results that are close to ideal 50%
            color = COLOR_GREEN if 45 <= pct <= 55 else COLOR_YELLOW
            if cycle == 1:
                color = COLOR_RED # Expected low avalanche on round 1
                
            print(f"    Round {cycle:2d}: {color}{pct:5.2f}%{COLOR_RESET}  {COLOR_GRAY}[{bar:<25}]{COLOR_RESET}")
        print()

def run_key_sensitivity_check(plaintext: str, key_str: str):
    """Runs a live key sensitivity check on the actual key and plaintext."""
    print_header("3. KEY SENSITIVITY ANALYSIS")
    print(f"  {COLOR_GRAY}Flipping each bit of the key and measuring how many{COLOR_RESET}")
    print(f"  {COLOR_GRAY}ciphertext bits change. Ideal target: ~50% change.{COLOR_RESET}\n")

    key = key_from_string(key_str)
    blocks = text_to_blocks(plaintext)
    ciphers = {
        "TEA": tea_encrypt,
        "MTEA (Proposed)": mtea_encrypt
    }

    cycles_to_check = [1, 8, 16, 24, 32]

    for name, encrypt_fn in ciphers.items():
        print(f"  {COLOR_BOLD}[{name}]{COLOR_RESET}")
        
        for cycle in cycles_to_check:
            total_bit_changes = 0
            total_tests = 0
            
            for block in blocks:
                ct_orig = encrypt_fn(block, key, cycle)
                # Flip each of the 128 bits in the key
                for bit_pos in range(128):
                    key_flipped = flip_bit_128(key, bit_pos)
                    ct_flipped = encrypt_fn(block, key_flipped, cycle)
                    total_bit_changes += count_diff_bits(ct_orig, ct_flipped)
                    total_tests += 1

            pct = (total_bit_changes / (total_tests * 64)) * 100
            bar_len = int(pct / 2)
            bar = "█" * bar_len
            
            color = COLOR_GREEN if 45 <= pct <= 55 else COLOR_YELLOW
            if cycle == 1:
                color = COLOR_RED
                
            print(f"    Round {cycle:2d}: {color}{pct:5.2f}%{COLOR_RESET}  {COLOR_GRAY}[{bar:<25}]{COLOR_RESET}")
        print()

def run_performance_check(encrypt_fn_map: dict):
    """Runs a quick performance benchmark using 20,000 blocks."""
    print_header("4. PERFORMANCE BENCHMARK (20,000 blocks)")
    print(f"  {COLOR_GRAY}Measuring encryption throughput in KB/s (32 rounds).{COLOR_RESET}\n")

    num_blocks = 20000
    key = [secrets.randbits(32) for _ in range(4)]
    blocks = [(secrets.randbits(32), secrets.randbits(32)) for _ in range(num_blocks)]

    for name, encrypt_fn in encrypt_fn_map.items():
        start_time = time.perf_counter()
        for b in blocks:
            _ = encrypt_fn(b, key, 32)
        end_time = time.perf_counter()
        
        elapsed = end_time - start_time
        # Each block is 8 bytes
        throughput = (num_blocks * 8) / (elapsed * 1024)
        
        print(f"  {COLOR_BOLD}{name:16s}{COLOR_RESET}: {COLOR_CYAN}{elapsed:.4f}s{COLOR_RESET}  ({throughput:.2f} KB/s)")

def main():
    print(f"\n{COLOR_CYAN}" + "#" * 65)
    print("#" + " " * 63 + "#")
    print(f"#   {COLOR_BOLD}{COLOR_WHITE}MTEA (Modified Tiny Encryption Algorithm) Demonstration{COLOR_RESET}{COLOR_CYAN}  #")
    print("#" + " " * 63 + "#")
    print("#" * 65 + COLOR_RESET)

    # 1. Ask user for plaintext input
    print(f"\n{COLOR_BOLD}Step 1: Plaintext Configuration{COLOR_RESET}")
    default_text = "The quick brown fox jumps over the lazy dog. Cryptography evaluation."
    print(f"  Default text: {COLOR_GRAY}\"{default_text}\"{COLOR_RESET}")
    
    user_input = input("  Enter custom plaintext (or press Enter to use default): ").strip()
    plaintext = user_input if user_input else default_text

    # 2. Automatically generate key
    print(f"\n{COLOR_BOLD}Step 2: Key Generation{COLOR_RESET}")
    generated_key = generate_random_key(16)
    print(f"  Generating random 128-bit key... {COLOR_GREEN}Success!{COLOR_RESET}")
    print(f"  Generated Key (16 ASCII chars): {COLOR_YELLOW}\"{generated_key}\"{COLOR_RESET}")
    
    input(f"\n  {COLOR_BOLD}Press Enter to run the cryptographic evaluation...{COLOR_RESET}")

    # 3. Core Encryption/Decryption Proof
    print_header("BASIC CORRECTNESS (Encrypt & Decrypt)")
    
    ciphers = ['TEA', 'MTEA']
    for cipher in ciphers:
        ct = encrypt_text(plaintext, generated_key, cipher.lower(), 32)
        recovered = decrypt_text(ct, generated_key, cipher.lower(), 32)
        
        status = f"{COLOR_GREEN}Success{COLOR_RESET}" if recovered == plaintext else f"{COLOR_RED}Failed{COLOR_RESET}"
        print(f"  {COLOR_BOLD}[{cipher}]{COLOR_RESET}")
        print(f"    Ciphertext (hex) : {ct[:64]}...")
        print(f"    Decrypted text   : \"{recovered}\"")
        print(f"    Integrity Check  : {status}\n")

    # 4. Run detailed cryptographic evaluation checks on these inputs
    run_equivalent_key_check(plaintext, generated_key)
    run_avalanche_check(plaintext, generated_key)
    run_key_sensitivity_check(plaintext, generated_key)
    
    # Run performance
    ciphers_map = {
        "TEA": tea_encrypt,
        "MTEA (Proposed)": mtea_encrypt
    }
    run_performance_check(ciphers_map)

    print(f"\n{COLOR_CYAN}{'='*65}{COLOR_RESET}")
    print(f"  {COLOR_GREEN}Evaluation complete!{COLOR_RESET} You can run this command again with other inputs.")
    print(f"{COLOR_CYAN}{'='*65}{COLOR_RESET}\n")

if __name__ == "__main__":
    main()
