# Combined CTF Writeup

This document combines every challenge from this session and the uploaded write-ups. It is written for a reader who is new to CTFs and cryptography.

**How to read the status labels**

- **Verified:** I ran the work myself in this session and checked the result.
- **Reported:** taken from the uploaded `solution-walkthrough.md` and the first uploaded write-up. The challenge files for these are not available to me, so I could not reproduce them. Treat them as claims until someone checks them.

---

## Part 0: Background

- **CTF (Capture The Flag):** a puzzle where you find a hidden string, usually in the form `genius{...}`.
- **Cipher:** an algorithm that turns readable text into unreadable text using a key.
- **PRNG (pseudo-random number generator):** an algorithm that produces numbers that look random but are fully determined by a starting value (the seed). If its outputs are predictable, so is anything built on them.
- **LCG (linear congruential generator):** the simplest PRNG type: `x_next = (a·x + c) mod M`.
- **ECDSA:** a signature scheme. A private key `d` signs a message hash `h` using a one-time nonce `k`, producing `(r, s)` with `s = k⁻¹(h + r·d) mod N`. If `k` is known or predictable, `d` can be solved for directly.
- **RSA:** a public-key cipher using `n = p·q`. It is secure only if `p` and `q` cannot be found from `n`.
- **Coppersmith's method:** a lattice technique (LLL reduction) that finds small unknowns in modular equations.
- **Feistel network:** a cipher structure that splits data into two halves and repeats a round function, swapping halves each round.
- **AES-CTR:** a stream mode where a nonce plus counter produce a keystream that is XORed with the data.
- **Base32 / Base64:** encodings that represent binary data as text. They are not encryption: anyone can reverse them.

---

## Part 1: Four Doors (archive flag)

The challenge had four files: a signing service (`signer.py`), its log (`log.txt`), a key ceremony (`vault.py` and `sealed.txt`), and an archive (`treadmill.bin` and `treadmill.py`). The hint said to count how many times the generator runs per signature, because the request ID shows only one of those outputs.

### 1.1 The signing log (Verified)

Each signature in `signer.py` calls the LCG four times:

1. `session = rng.next()` — this is the request ID written to the log.
2. Three more calls build the 192-bit nonce `k`.

So the logged request IDs are every fourth LCG output. I used the 48 logged IDs to find the stride-4 recurrence:

```text
x[i+1] = A·x[i] + C   (mod M),     M = 2^64 - 59
A = a⁴,   C = c·(1 + a + a² + a³)
```

Two consecutive logged IDs give `A` and `C`. A third check confirmed the recurrence held across all 48 entries.

```text
A = 4905618893419107788
C = 11582435309231040088
```

`a` is a fourth root of `A`, which has four candidates modulo `M`. For each, `c = C / (1 + a + a² + a³)`. Each `(a, c)` pair gives a nonce for every signature, and then `d = (s·k − h)·r⁻¹ mod N`. Only one candidate produced the same `d` for all three signatures I checked:

```text
a = 2405495461026967474
c = 4921282118604643118
d = 82edb1ff8cd6f0d496c152f9430011f167eb3922c83f62a011278e4439592ca7
```

**Why the check matters:** wrong candidates give different values of `d` for each signature. The right candidate gives one value every time.

### 1.2 The key ceremony (Verified)

`vault.py` builds the RSA prime `p` as:

```text
p = (prefix << 112) | (112 random bits) | 1
prefix = SHAKE-256(d || "vault-kdf-v1") → 400 bits, with the top bit set
```

Since `d` is now known, the top 400 bits of `p` are known. The unknown part is only 112 bits. I set up the univariate polynomial `f(x) = x + P0`, where `P0 = prefix << 112`, and applied Coppersmith's method using polynomials `x^j · f(x)^i · n^(m−i)` with `m = t = 3`. LLL reduction (fpylll) gave a polynomial with the root.

One detail mattered: the lattice rows are scaled by `X^j` where `X = 2^112`, so the root I needed is `y = x/X`, and `x = X·y`. I first got this wrong and found no root, then fixed the scaling and it worked.

The result: `p` and `q` are both 512-bit primes, with `p·q = n`.

Decrypting the sealed ciphertext with the standard RSA formula gave the 32-byte secret:

```text
e102b4a561b135682edbbfc4d0f9919ed50a634f87050e52fcffd5b799d92330
```

### 1.3 The archive layout (Verified)

`treadmill.bin` starts with an 8-byte nonce. The rest is AES-256-CTR ciphertext keyed with the 32-byte secret. Decrypting it gives:

```text
u32 N                                  → N = 262144
N × (u32 plaintext, u32 ciphertext)    under the archive cipher
u32 L                                  → L = 44
L bytes: the flag, encrypted, 4-byte blocks, PKCS#7 padded
```

### 1.4 The Treadmill cipher (Verified for the key)

`treadmill.py` is a 32-round Feistel cipher on 32-bit blocks split into 16-bit halves. Its round function is:

```text
F(x) = ROL16( ((x + k0) mod 2^16) XOR k1 , 5 ) + k2   (mod 2^16)
round: (L, R) → (R, L XOR F(R))
```

The key is three 16-bit words `(k0, k1, k2)`, which is 48 bits total.

**What I tried myself and could not solve:** I checked many simple key sources (slices of `d`, the secret, `a`, `c`, the nonce, and LCG outputs, plus date-based and small seeds). None matched. I could not recover the key by brute force on this machine, which has one core.

**Reported method (from the uploaded write-up, not reproduced by me):** the key was found with a slide attack. Because all 32 rounds use the same `F`, a single round `T` commutes with its own powers: `E(T(P)) = T(E(P))`. Pairs of archive records that are one round apart reveal samples of `F`, which constrain the key. The reported key is:

```text
k0 = 32117,  k1 = 18817,  k2 = 44463
```

**Verified:** I tested this key against all 262,144 archive pairs, and every pair matched. That makes the key correct, whatever method found it.

### 1.5 The flag (Verified)

Decrypting the 44-byte flag block by block with `dec_block` and this key gives:

```text
genius{slid3_4w4y_fr0m_th3_tr34dm1ll_5e1a}\x02\x02
```

The two `0x02` bytes are PKCS#7 padding. Removing them leaves:

```text
genius{slid3_4w4y_fr0m_th3_tr34dm1ll_5e1a}
```

**Correction:** my earlier writeup said the archive flag was unrecovered. That was true at the time, but the key is now verified and the flag is decrypted.

---

## Part 2: Challenges reported only (not verified by me)

These come from the uploaded write-ups. Their challenge files are not in my environment, so I could not reproduce any of them.

### 2.1 Custom Feistel cipher (Reported)

- **Claimed cipher:** round function `f(x, k) = rotl(x,5) ⊕ rotl(x,13) ⊕ (x >> 3) ⊕ k`, with 8 round keys.
- **Claimed method:** every operation is linear over GF(2), so the round keys satisfy a linear system. Gaussian elimination on many known plaintext/ciphertext pairs recovers the 256 key bits.
- **Claimed flag:** `genius{xor_all_the_way_down_7f3a}`

Why this is plausible: XOR, rotations, and shifts are linear over GF(2), so a cipher built only from them can be solved with linear algebra. Real ciphers add non-linear parts (S-boxes) to prevent this.

### 2.2 Network forensics, `hunt.pcap` (Reported)

- **Claimed approach:** DNS queries carried encrypted data in subdomain labels (`...sync.cdn-edge.net`). An HTTP response to the gateway gave a key recipe: `key = SHA-256(token + "-" + X-Part)`, with `blob = IV(16 bytes) || AES-CBC(zlib(document))`.
- **Claimed host:** 10.13.37.77, token `saffron-marble`, X-Part `juniper-thistle`.
- **Claimed flag:** `genius{every_packet_tells_a_story_8c1e}`

Lesson: DNS is a common channel for hiding data, and a key often comes from combining two values from the traffic.

### 2.3 Auth Relay (Reported)

- **Claimed approach:** a stripped ELF binary. When the relay at a documentation address is unreachable, the program falls back to a cached key and checks the input byte by byte with a position-dependent transform. Inverting the transform gives the key.
- **Claimed flag:** `genius{f4llb4ck_k3y_w4s_th3_r34l_on3}`

### 2.4 Shuffle64 (Reported)

- **Claimed approach:** Base64 with a shuffled 64-character alphabet. Map each character to its position in the custom alphabet, then to the same position in standard Base64, then decode.
- **Claimed flag:** `genius{c0st0m_4lph4b3t_b64}`

### 2.5 Rot Vault (Reported)

- **Claimed approach:** each byte is transformed as `stored = ROL8(input, 3) XOR 0xA5`. Invert it with `input = ROR8(stored XOR 0xA5, 3)`.
- **Claimed flag:** `genius{r0l_th3n_x0r_1s_3z}`

---

## Part 3: Challenges I verified in this session

### 3.1 Layered encodings (Verified)

Input:

```text
K5VEUV3EK5DFSVTOOBWE223LO5KGYUSPLJWFMNSSNJJGWU2HPBEFIVLIK5SVMZ3XJVCEET2WI5HDMWJSO42E6VSCLFGUIMB5-
```

1. The trailing `-` is not part of the data. Remove it.
2. The rest uses only `A–Z` and `2–7`, so it is Base32. Decoding gives a Base64 string: `WjJWdWFYVnplMkkwTlROZlV6RjRkSGxHTUhWeVgwMDBOVGN6Y2w4OVBYMD0=`
3. Decoding that gives another Base64 string.
4. Decoding again gives the plaintext: `genius{b453_S1xtyF0ur_M4573r_==}`

The `==` is part of the flag text, not Base64 padding at the last step.

Caveat: this flag is in the flag format, but I did not confirm it belongs to the Four Doors challenge.

### 3.2 Julius's message: Caesar cipher (Verified)

Input:

```text
nlupbz{jhlzhy_dhz_h_ibzf_thu}
```

The first word has the same letter pattern as `genius`. Each letter is 7 places later in the alphabet than the plaintext letter, so shift back by 7:

```text
genius{caesar_was_a_busy_man}
```

A forward shift of 19 gives the same result, since the alphabet wraps after 26 letters.

### 3.3 Dock allocation memo: hidden text in a .docx (Verified)

A .docx file is a ZIP archive of XML. I unpacked it and searched `word/document.xml` for `w:vanish`, the Word property that hides text from display but keeps it in the file. There was one hidden run, the "Draft reference" line:

```text
genius{h1dd3n_runs_st1ll_r34d_b8c76f11}
```

The metadata (author, last editor, dates), `customXml`, and `custom.xml` contained nothing else relevant. There were no comments or tracked changes. The archive password given with the challenge was not needed, because the input was a single .docx file.

---

## Summary

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| Four Doors (archive) | LCG stride-4 recurrence, ECDSA nonce recovery, Coppersmith factoring, AES-CTR, Feistel key check | `genius{slid3_4w4y_fr0m_th3_tr34dm1ll_5e1a}` | Verified (key and flag) |
| Custom Feistel | Gaussian elimination over GF(2) | `genius{xor_all_the_way_down_7f3a}` | Reported |
| Network forensics (PCAP) | DNS exfiltration, key from token + X-Part | `genius{every_packet_tells_a_story_8c1e}` | Reported |
| Auth Relay | Fallback key, inverted byte transform | `genius{f4llb4ck_k3y_w4s_th3_r34l_on3}` | Reported |
| Shuffle64 | Base64 with custom alphabet | `genius{c0st0m_4lph4b3t_b64}` | Reported |
| Rot Vault | ROL8 + XOR, inverted | `genius{r0l_th3n_x0r_1s_3z}` | Reported |
| Layered encodings | Base32 → Base64 → Base64 | `genius{b453_S1xtyF0ur_M4573r_==}` | Verified (not linked to Four Doors) |
| Julius's message | Caesar shift of 7 | `genius{caesar_was_a_busy_man}` | Verified |
| Dock memo (.docx) | Hidden `w:vanish` text | `genius{h1dd3n_runs_st1ll_r34d_b8c76f11}` | Verified |

## Lessons across the challenges

1. **Look for structure, not just the visible output.** The stride-4 pattern, the repeated Feistel rounds, the hidden .docx run, and the layered encodings all came from looking beyond the surface.
2. **Predictable randomness breaks cryptography.** The signing nonces came from a simple LCG. Once its structure was known, the private key followed.
3. **Derived values leak information.** The top bits of the RSA prime came from the private key, which made factoring feasible.
4. **Verify every candidate.** Wrong candidates for `(a, c)`, for the key, and for the decoding all fail a consistency check. Only the correct one passes all of them.
5. **Know what you have verified.** Keep reported results separate from checked ones, and check a claim before presenting it as solved.
