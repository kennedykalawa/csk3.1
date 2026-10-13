# Puzzle solutions: a beginner-friendly walkthrough

This document explains the challenges we solved in this conversation. The main idea in each one is to identify the operation that produced the visible text or data, then reverse that operation. Some challenges are simple encodings; the vault and archive challenges require tracing how the program works.

> These are puzzle solutions. The binary reverse-engineering examples below refer only to the challenge files supplied in `/home/ktec/Downloads`.

## 1. Four Doors: recover the archive flag

The files were in `/home/ktec/Downloads/fourdoors_jl0w1i`. The challenge included a signing service, its log, a key ceremony, and an encrypted archive. The hint said to count how many times the random-number generator runs per signature, and that the request ID shows only one output.

### Step 1: Understand what each signature consumes

In `signer.py`, each signature makes four calls to the linear congruential generator (LCG):

1. `session = rng.next()` produces the request ID recorded in the log.
2. Three more calls are joined to form the ECDSA nonce `k`.

The LCG state is updated by:

```text
x_next = (a * x + c) mod M
```

So the logged request IDs are every fourth state, rather than consecutive states. If two adjacent logged IDs are `x[i]` and `x[i+1]`, then:

```text
x[i+1] = (A * x[i] + C) mod M
A = a^4 mod M
C = c * (1 + a + a^2 + a^3) mod M
```

The code gives `M = 2^64 - 59`. With several request IDs, the observed recurrence determines `A` and `C` modulo `M`. The remaining task is to find an `a` whose fourth power is `A`, then derive `c` from `C`. There are several possible fourth roots, so each candidate must be checked against the signatures.

### Step 2: Use the reconstructed nonces to recover the signing key

For each candidate LCG, generate the three nonce pieces after each request ID and combine them exactly as the signer does:

```text
k = (output_1 << 128) | (output_2 << 64) | output_3
```

ECDSA signs a message hash `h` using private key `d`, nonce `k`, and signature `(r, s)`:

```text
s = k^-1 * (h + r*d) mod N
```

Rearranging lets us calculate the private key from a known nonce and signature:

```text
d = (s*k - h) * r^-1 mod N
```

Only one LCG candidate produced the same `d` for every one of the 48 logged signatures. That gives a strong check that both the RNG reconstruction and nonce alignment are right. The recovered private key was:

```text
82edb1ff8cd6f0d496c152f9430011f167eb3922c83f62a011278e4439592ca7
```

### Step 3: Use the signing key to factor the ceremony modulus

`vault.py` derives a 400-bit prefix from the signing key using SHAKE-256. The prime `p` is made by placing that known prefix above 112 unknown low bits:

```text
p = (prefix << 112) | unknown_low_bits
```

The ceremony output gives the RSA modulus `n = p*q`. Since the high bits of one factor are known and only 112 bits remain unknown, this is a small-root problem. A Coppersmith-style lattice reduction (LLL) recovers the low bits and therefore `p`; dividing `n` by `p` gives `q`.

The RSA ciphertext can then be decrypted with the private exponent derived from `p` and `q`. The resulting 32-byte secret was:

```text
e102b4a561b135682edbbfc4d0f9919ed50a634f87050e52fcffd5b799d92330
```

### Step 4: Decrypt the archive and recover its block-cipher key

The secret is the AES-256 key for `treadmill.bin`. The first eight bytes of that file are the CTR nonce. Decrypting the rest with AES-256-CTR reveals this layout:

```text
u32 N
N records of (u32 plaintext_block, u32 ciphertext_block)
u32 L
L bytes of encrypted flag data
```

Here `N` is 262,144. The block cipher in `treadmill.py` is a 32-round Feistel network. Every round uses the same 48-bit key, split into three 16-bit values `(k0, k1, k2)`. Its round function is:

```text
F(x) = (ROL16((((x + k0) mod 2^16) XOR k1), 5) + k2) mod 2^16
```

The round maps two 16-bit halves as `(L, R) -> (R, L XOR F(R))`. Reusing the same round over and over makes a **slide attack** possible.

Call one round `T`; then the full encryption is `E = T^32`. Because `T` commutes with its own powers:

```text
E(T(P)) = T(E(P))
```

The known plaintext/ciphertext table lets us look for records that could be one round apart. If `Pj = T(Pi)`, then the left half of `Pj` must equal the right half of `Pi`; the same relationship must hold between the ciphertext halves. These half matches provide candidate input/output samples for `F`. Most are accidental matches, so candidates are checked together against the repeated table evidence.

The recovered round-key components were:

```text
k0 = 32117
k1 = 18817
k2 = 44463
```

As a verification, this key correctly encrypts every one of the 262,144 plaintext blocks to its paired ciphertext block.

### Step 5: Decrypt and unpad the flag

The final encrypted portion is decrypted block by block with the inverse Feistel rounds. Its PKCS#7 padding is two `0x02` bytes. Removing those bytes gives:

```text
genius{slid3_4w4y_fr0m_th3_tr34dm1ll_5e1a}
```

---

## 2. Auth Relay: take the connection-failure path

The file was `/home/ktec/Downloads/auth_relay_1_bb64jn`, a small stripped ELF executable. `strings` showed messages about requesting a session key and falling back to a cached default key. The relay address was `198.51.100.42`, an address reserved for documentation rather than a real service.

### Step 1: Follow the network function

The program creates a socket and attempts a connection. When the relay is unreachable, it prints:

```text
Relay unreachable. Using cached default key.
```

It then prompts for `key>` and checks the supplied text locally. The fallback is the key to this puzzle: we do not need a working server to reach the password check.

### Step 2: Reverse the local byte check

The checker requires exactly 37 characters. For each position `i`, it combines the input byte with a small position-based value and compares the result with a stored byte. In simplified form, its check is:

```text
stored[i] == ((5*i + input[i]) mod 256) XOR ((i mod 11) - 102 mod 256)
```

Although the prompt emphasizes how the session key is populated, the password comparison is still a byte-by-byte transformation. We can invert it by trying printable characters at each position and keeping the one that reproduces the stored byte. This yields:

```text
genius{f4llb4ck_k3y_w4s_th3_r34l_on3}
```

Entering that string after the connection-failure fallback makes the program print `Auth relay confirms. Correct!`.

---

## 3. Shuffle64: Base64 with a different alphabet

The file `/home/ktec/Downloads/shuffle64_1_nzdwts` stores this encoded value:

```text
M2CxqBCmt2Dve3JvwC80wIWgFUOmrY9oFpK9
```

The program also contains a 64-character alphabet:

```text
QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789+/
```

Base64 works by converting groups of three bytes into four six-bit values, then representing those values as characters from an alphabet. Here, the six-bit values are arranged as usual, but the alphabet is shuffled. To decode it:

1. Find each encoded character's position in the program's custom alphabet.
2. Replace it with the character at that same position in the standard Base64 alphabet (`A-Z`, `a-z`, `0-9`, `+`, `/`).
3. Base64-decode the translated text.

The result is:

```text
genius{c0st0m_4lph4b3t_b64}
```

The supplied executable confirmed it with `Correct!`.

---

## 4. Rot Vault: undo the per-character transform

The file `/home/ktec/Downloads/rot_vault_1_oeqjb4` stores 26 transformed bytes. Its check operates on each character independently of its position:

```text
stored_byte = ROL8(input_byte, 3) XOR 0xA5
```

`ROL8` means rotate an 8-bit value left by three bits. XOR is its own inverse, so first XOR the stored byte with `0xA5`. Then rotate right by three bits to undo the left rotation:

```text
input_byte = ROR8(stored_byte XOR 0xA5, 3)
```

Applying that to all 26 bytes produces:

```text
genius{r0l_th3n_x0r_1s_3z}
```

The program prints `Vault opened!` for that code.

---

## 5. “Simplest encoding”: Base32, then Base64 twice

The message was:

```text
K5VEUV3EK5DFSVTOOBWE223LO5KGYUSPLJWFMNSSNJJGWU2HPBEFIVLIK5SVMZ3XJVCEET2WI5HDMWJSO42E6VSCLFGUIMB5-
```

The final hyphen is outside the encoded data. The remaining characters use the Base32 alphabet (`A-Z` and `2-7`), so decode as Base32 first. The layers are:

```text
Base32 decode:
5a3256756158567a6532786865575679633139316347397558327868655756796333303d

Hex decode:
Z2VuaXVze2I0NTNfUzF4dHlGMHVyX000NTczcl89PX0=

Base64 decode:
genius{b453_S1xtyF0ur_M4573r_==}
```

The `==` characters are part of the decoded flag text; they are not Base64 padding at that final layer.

---

## 6. Julius and his generals: Caesar shift

The ciphertext is:

```text
nlupbz{jhlzhy_dhz_h_ibzf_thu}
```

The first word `nlupbz` has the same pattern as `genius`. Each ciphertext letter is seven places later in the alphabet than the plaintext letter (`n` is seven after `g`, `l` seven after `e`, and so on). Shift each lowercase letter back by seven, preserving braces and underscores:

```text
genius{caesar_was_a_busy_man}
```

Equivalently, a Caesar shift of 19 places forward gives the same result, because the alphabet wraps around after 26 letters.

---

## Answers at a glance

| Challenge | Recovered answer |
|---|---|
| Four Doors | `genius{slid3_4w4y_fr0m_th3_tr34dm1ll_5e1a}` |
| Auth Relay | `genius{f4llb4ck_k3y_w4s_th3_r34l_on3}` |
| Shuffle64 | `genius{c0st0m_4lph4b3t_b64}` |
| Rot Vault | `genius{r0l_th3n_x0r_1s_3z}` |
| Base32 / hex / Base64 layers | `genius{b453_S1xtyF0ur_M4573r_==}` |
| Caesar cipher | `genius{caesar_was_a_busy_man}` |
