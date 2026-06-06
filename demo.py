"""
demo.py
Interactive plaintext encryption/decryption demo for TEA, MTEA, and XTEA.
Allows the user to:
  - Enter a plaintext string and key
  - Encrypt it with all three ciphers
  - See the hex ciphertext output
  - Verify decryption recovers the original text
  - Visually compare ciphertext differences when plaintext changes by one character
"""

from tea_core import (
    encrypt_text, decrypt_text,
    text_to_blocks, key_from_string,
    tea_encrypt, mtea_encrypt, xtea_encrypt,
    blocks_to_hex
)


def print_section(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def compare_hex(hex1: str, hex2: str) -> str:
    """Return a visual diff showing which nibbles differ between two hex strings."""
    result = ""
    for a, b in zip(hex1.replace(' ', ''), hex2.replace(' ', '')):
        result += b if a != b else '·'
    return result


def run_encryption_demo(plaintext: str, key_str: str, cycles: int = 32):
    """Encrypt plaintext with all three ciphers and show results."""
    print_section("ENCRYPTION DEMO")
    print(f"  Plaintext : \"{plaintext}\"")
    print(f"  Key       : \"{key_str}\"")
    print(f"  Cycles    : {cycles}")
    print()

    ciphers = ['TEA', 'MTEA', 'XTEA']
    ciphertexts = {}

    for cipher in ciphers:
        ct = encrypt_text(plaintext, key_str, cipher.lower(), cycles)
        ciphertexts[cipher] = ct
        print(f"  [{cipher:4s}] Ciphertext (hex):")
        print(f"         {ct}")

    return ciphertexts


def run_decryption_demo(ciphertexts: dict, key_str: str, cycles: int = 32):
    """Decrypt ciphertexts and verify correctness."""
    print_section("DECRYPTION VERIFICATION")

    for cipher, ct in ciphertexts.items():
        recovered = decrypt_text(ct, key_str, cipher.lower(), cycles)
        print(f"  [{cipher:4s}] Recovered : \"{recovered}\"")


def run_wrong_key_demo(plaintext: str, key_str: str, cycles: int = 32):
    """Show that a wrong key produces garbage decryption."""
    print_section("WRONG KEY DECRYPTION (should produce garbled text)")
    wrong_key = key_str[:-1] + ('X' if key_str[-1] != 'X' else 'Y')

    ciphers = ['TEA', 'MTEA', 'XTEA']
    for cipher in ciphers:
        ct = encrypt_text(plaintext, key_str, cipher.lower(), cycles)
        bad_decryption = decrypt_text(ct, wrong_key, cipher.lower(), cycles)
        print(f"  [{cipher:4s}] With wrong key \"{wrong_key}\": \"{bad_decryption}\"")


def run_avalanche_demo(plaintext: str, key_str: str, cycles: int = 32):
    """
    Change a single character in the plaintext and show how the ciphertext
    changes drastically — visual demonstration of the avalanche effect.
    """
    print_section("AVALANCHE EFFECT DEMO (1-character plaintext change)")
    print(f"  Original  : \"{plaintext}\"")

    # Modify the first character by one ASCII value
    modified_char = chr(ord(plaintext[0]) + 1)
    modified = modified_char + plaintext[1:]
    print(f"  Modified  : \"{modified}\"  (changed '{plaintext[0]}' -> '{modified_char}')")
    print()

    key = key_from_string(key_str)
    ciphers = {
        'TEA': tea_encrypt,
        'MTEA': mtea_encrypt,
        'XTEA': xtea_encrypt,
    }

    for cipher_name, encrypt_fn in ciphers.items():
        blocks_orig = text_to_blocks(plaintext)
        blocks_mod = text_to_blocks(modified)

        ct_orig_blocks = [encrypt_fn(b, key, cycles) for b in blocks_orig]
        ct_mod_blocks = [encrypt_fn(b, key, cycles) for b in blocks_mod]

        ct_orig_hex = blocks_to_hex(ct_orig_blocks).replace(' ', '')
        ct_mod_hex = blocks_to_hex(ct_mod_blocks).replace(' ', '')

        # Count differing bits
        diff_bits = 0
        for b1, b2 in zip(ct_orig_blocks, ct_mod_blocks):
            diff0 = bin((b1[0] ^ b2[0]) & 0xFFFFFFFF).count('1')
            diff1 = bin((b1[1] ^ b2[1]) & 0xFFFFFFFF).count('1')
            diff_bits += diff0 + diff1

        total_bits = len(ct_orig_blocks) * 64
        pct = (diff_bits / total_bits) * 100

        diff_visual = compare_hex(ct_orig_hex, ct_mod_hex)

        print(f"  [{cipher_name:4s}]")
        print(f"    Original CT : {ct_orig_hex}")
        print(f"    Modified CT : {ct_mod_hex}")
        print(f"    Differences : {diff_visual}  ({diff_bits}/{total_bits} bits = {pct:.1f}%)")
        print()


def run_equivalent_key_demo(plaintext: str, key_str: str, cycles: int = 32):
    """
    Demonstrate TEA's equivalent key vulnerability vs MTEA's resistance.
    TEA: flipping MSB of all 4 key words (K ^ [MSB, MSB, MSB, MSB]) encrypts identically.
    MTEA: this produces a different ciphertext.
    """
    print_section("EQUIVALENT KEY VULNERABILITY DEMO")
    print("  TEA has a known flaw: up to 3 other keys produce identical ciphertext.")
    print("  MTEA's dynamic key schedule eliminates this weakness.")
    print()

    key = key_from_string(key_str)
    msb = 0x80000000
    key_equiv = [k ^ msb for k in key]

    blocks = text_to_blocks(plaintext)
    ciphers = {
        'TEA': tea_encrypt,
        'MTEA': mtea_encrypt,
        'XTEA': xtea_encrypt,
    }

    for cipher_name, encrypt_fn in ciphers.items():
        ct1_blocks = [encrypt_fn(b, key, cycles) for b in blocks]
        ct2_blocks = [encrypt_fn(b, key_equiv, cycles) for b in blocks]

        ct1 = blocks_to_hex(ct1_blocks)
        ct2 = blocks_to_hex(ct2_blocks)

        same = (ct1 == ct2)
        status = "VULNERABLE (same ciphertext!)" if same else "SECURE (different ciphertext)"

        print(f"  [{cipher_name:4s}] Original key CT   : {ct1}")
        print(f"         MSB-flipped key CT : {ct2}")
        print(f"         Result: {status}")
        print()


def main():
    print("\n" + "#" * 60)
    print("#   TEA / MTEA / XTEA — Plaintext Encryption Demo        #")
    print("#" * 60)

    # --- Default demo ---
    plaintext = "Hello, World! This is a TEA cipher test."
    key_str = "SecretKey123456"
    cycles = 32

    # You can change these or accept user input below
    print(f"\n  Using default plaintext : \"{plaintext}\"")
    print(f"  Using default key       : \"{key_str}\"")
    use_custom = input("\n  Enter custom plaintext? (y/n, default n): ").strip().lower()

    if use_custom == 'y':
        plaintext = input("  Enter plaintext: ").strip() or plaintext
        key_str = input("  Enter key (up to 16 chars): ").strip() or key_str
        try:
            cycles = int(input("  Rounds/cycles (default 32): ").strip() or "32")
        except ValueError:
            cycles = 32

    # Run all demos
    ciphertexts = run_encryption_demo(plaintext, key_str, cycles)
    run_decryption_demo(ciphertexts, key_str, cycles)
    run_wrong_key_demo(plaintext, key_str, cycles)
    run_avalanche_demo(plaintext, key_str, cycles)
    run_equivalent_key_demo(plaintext, key_str, cycles)

    print("\n" + "#" * 60)
    print("#   Run evaluator.py for full statistical analysis        #")
    print("#" * 60 + "\n")


if __name__ == "__main__":
    main()
