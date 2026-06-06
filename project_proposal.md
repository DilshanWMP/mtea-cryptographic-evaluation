# Project Proposal

**Title:** Enhancing the Cryptographic Security of the Tiny Encryption Algorithm (TEA) via a Dynamic Round-Dependent Key Schedule

---

## 1. Problem Statement
The Tiny Encryption Algorithm (TEA) is a highly efficient, lightweight Feistel-network block cipher designed for resource-constrained systems. Despite its simplicity and speed, TEA suffers from a major cryptographic vulnerability: **equivalent keys**. Every 128-bit key has three other equivalent keys that generate identical ciphertexts for any given plaintext. This reduces the effective key size from 128 bits to 126 bits, leaving it vulnerable to related-key attacks and reducing brute-force complexity. 

While the Extended Tiny Encryption Algorithm (XTEA) mitigates this by introducing a more complex index-based key schedule, it increases structural complexity. There is a need for a lightweight, alternative key-scheduling enhancement that eliminates the equivalent key vulnerability while maintaining the core structural simplicity of TEA.

---

## 2. Objectives
1. **Implement and Validate:** Implement the core TEA and XTEA algorithms alongside a proposed Modified TEA (MTEA).
2. **Eliminate Key Equivalence:** Develop a lightweight, dynamic, round-dependent key schedule for MTEA using sum-dependent bitwise rotations.
3. **Experimental Verification:** Construct a test suite to experimentally measure:
   * Presence of equivalent keys.
   * Plaintext avalanche effect (diffusion rate across rounds).
   * Key sensitivity characteristics.
   * Encryption throughput and execution performance.
4. **Comparative Analysis:** Critically analyze the security gains of MTEA against the performance trade-offs compared to TEA and XTEA.

---

## 3. Methodology & Proposed Modification
In the original TEA, the subkeys ($K_0, K_1, K_2, K_3$) applied in each Feistel round are static. Because of this, flipping the most significant bit (MSB) of key words can cancel out during the addition and bitwise shift steps, creating equivalent keys.

The proposed **MTEA** introduces a dynamic, sum-dependent bitwise rotation to the key words before they are applied in each round:
$$\text{Round Key } K_i = (K_i \lll (\text{sum} \gg (5 \times i)) \bmod 32)$$
This ensures that key bits change their positions dynamically at each cycle, preventing static bit flips from canceling out and effectively eliminating the equivalent key vulnerability.

---

## 4. Scope
* **Language/Platform:** Python 3.x.
* **Algorithms Implemented:** TEA (baseline), XTEA (industry reference), and MTEA (proposed modification).
* **Evaluation Metrics:**
  * Exhaustive search of all $2^4 - 1 = 15$ MSB-flip key differences to detect equivalent keys.
  * Statistical avalanche effect (percentage of ciphertext bits changed per bit-flip in plaintext over 1 to 32 cycles).
  * Key sensitivity (percentage of ciphertext bits changed per bit-flip in key over 1 to 32 cycles).
  * Performance benchmarking (throughput in KB/s and execution time for 50,000 blocks).
