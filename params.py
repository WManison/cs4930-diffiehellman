"""The public numbers every Diffie-Hellman run in this lab uses. Given; do not change it.

A Diffie-Hellman group is two public numbers: a prime modulus p and a
generator g. Everyone, the eavesdropper included, knows both.

    TOY_G, TOY_P      g = 5, p = 23: the numbers from class, small enough to
                      do by hand
    GROUP14_G/_P      the 2048-bit group from RFC 3526, section 3 ("group 14"),
                      the size real protocols such as SSH and IPsec have used
    SIZES             small groups for the brute-force experiment, one per
                      prime size: {bits: (g, p)}

Every prime in SIZES is a "safe prime" (p = 2q + 1 with q also prime) and g
generates all of 1 .. p-1, so a private key can be any exponent from 2 to
p - 2, and a brute-force search may have to try nearly all of them.

RFC 3526: https://www.rfc-editor.org/rfc/rfc3526#section-3
"""

TOY_G = 5
TOY_P = 23

# RFC 3526 gives this prime as 2^2048 - 2^1984 - 1 + 2^64 * ([2^1918 pi] + 124476).
# The hex below is copied from the RFC, in the RFC's own groups of eight digits.
GROUP14_G = 2
GROUP14_P = int("".join("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
""".split()), 16)

# The largest safe prime below 2^bits, and its smallest generator.
SIZES = {
    16: (2, 65267),
    20: (5, 1048343),
    24: (2, 16776899),
    28: (2, 268435019),
}
