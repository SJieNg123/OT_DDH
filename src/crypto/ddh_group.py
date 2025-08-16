# src/crypto/ddh_group.py
import secrets

class DDHGroup:
    """
    Represents a cyclic group where the Decisional Diffie-Hellman (DDH)
    assumption is believed to hold.

    This class uses pre-defined, standard "safe" prime and generator values.
    Generating secure parameters from scratch is a complex process. Using
    standardized parameters is a common and secure practice.

    The parameters used here are for demonstration purposes.
    """

    def __init__(self):
        """
        Initializes the group with a pre-defined 2048-bit safe prime (p)
        and a generator (g), as defined in RFC 3526.
        """
        # RFC 3526 - 2048-bit MODP Group
        self.p = int("""
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
                    """.replace(" ", "").replace("\n", ""), 16)
        self.g = 2
        print(f"DDH Group initialized with a {self.p.bit_length()}-bit prime.")

    def power(self, base: int, exp: int) -> int:
        """
        Computes (base^exp) mod p.
        This is the core operation for the multiplication-respecting synthesizer.
        For example, g^(x1 * x2) is computed as power(g, x1 * x2).
        """
        
        # Ensure base is in the range [0, p-1]
        base = base % self.p
        return pow(base, exp, self.p)

    def get_random_exponent(self) -> int:
        """
        Generates a cryptographically secure random exponent.
        The sender uses this to generate the secret key pairs (a_j^0, a_j^1)
        and the blinding factors (r_j) for the transfer phase. [cite: 469, 472]

        The exponent should be in the range [1, p-1].

        Returns:
            A random integer.
        """
        # The order of the multiplicative group Z_p* is p-1.
        # We generate a random number in the range [0, p-2] and add 1.
        return secrets.randbelow(self.p - 1) + 1