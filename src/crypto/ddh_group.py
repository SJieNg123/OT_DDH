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
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
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