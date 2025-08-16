# src/roles/adaptive_sender.py
import math
import hashlib
from src.crypto.ddh_group import DDHGroup
from src.crypto.commitment import CommitmentScheme
from src.utils.bitops import int_to_bitlist

class AdaptiveSender:
    """
    Implements the Sender's logic for the Adaptive OT Protocol (Protocol 3.2).

    The sender performs a one-time setup to commit to all N messages.
    Then, for each transfer request from the receiver, the sender provides
    blinded values that allow the receiver to learn exactly one message.
    """

    def __init__(self, messages: list[bytes], crypto_group: DDHGroup):
        """
        Initializes the sender with their list of secret messages and the DDH group.
        """
        assert all(len(m) == len(messages[0]) for m in messages), "All messages must have the same length."
        self.messages = messages
        self.N = len(messages)
        self.l = int(math.log2(self.N))
        self.msg_len = len(messages[0])
        self.group = crypto_group
        self.commitment_scheme = CommitmentScheme()
        
        # This will store the secret exponents after initialization
        self.secret_exponents: list[tuple[int, int]] = []

    def initialize_database(self) -> list[bytes]:
        """
        Performs the one-time Initialization phase of Protocol 3.2. 

        This involves generating secret exponents, creating commitment keys
        for every message using the DDH synthesizer, and committing to them.

        Returns:
            A list of N commitments, one for each message.
        """
        print("Sender: Performing one-time database initialization...")
        
        # 1. B prepares l random pairs of keys (exponents in our case) [cite: 527]
        # (a_1^0, a_1^1), (a_2^0, a_2^1), ..., (a_l^0, a_l^1)
        self.secret_exponents = [
            (self.group.get_random_exponent(), self.group.get_random_exponent())
            for _ in range(self.l)
        ]

        commitments = []
        self.commitment_keys = [] # Store for verification later

        # For each message X_I, create a commitment Y_I
        for i in range(self.N):
            # For each message I, its bit representation is i_1, ..., i_l 
            index_bits = int_to_bitlist(i, self.l)
            
            # Compute the product of the corresponding secret exponents
            exp_product = 1
            for j, bit in enumerate(index_bits):
                exp_product *= self.secret_exponents[j][bit]

            # The commitment key K_I is h(g^(product of exponents)) 
            # We use a simple hash (h) of the group element's byte representation.
            synthesizer_output = self.group.power(self.group.g, exp_product)
            key_K_I = hashlib.sha256(str(synthesizer_output).encode()).digest()
            self.commitment_keys.append(key_K_I) # Save for later

            # Commit to the message X_I using the key K_I 
            commitment = self.commitment_scheme.commit(self.messages[i], key_K_I)
            commitments.append(commitment)
        
        print(f"Sender: {self.N} commitments created.")
        return commitments

    def prepare_transfer_values(self) -> tuple[list[tuple[int, int]], int]:
        """
        Prepares the values needed for a single interactive transfer. 
        This corresponds to steps 2a, 2b, and 2c in Protocol 3.2.

        Returns:
            A tuple containing:
            - A list of blinded exponent pairs for the OT channel.
            - The final blinding factor's inverse to be sent to the receiver.
        """
        from math import gcd

        while True:
            # 1. B chooses random elements r_1, ..., r_l 
            r_values = [self.group.get_random_exponent() for _ in range(self.l)]

            # 2. Compute r_product and check invertibility
            r_product = 1
            for r in r_values:
                r_product *= r

            if gcd(r_product, self.group.p - 1) == 1:
                break
            else:
                print("Retrying: r_product not invertible mod (p-1)")

        # 3. For each j, create the blinded pairs <a_j^0 * r_j, a_j^1 * r_j> 
        blinded_exponent_pairs = []
        for j in range(self.l):
            a0, a1 = self.secret_exponents[j]
            r = r_values[j]
            blinded_a0 = a0 * r
            blinded_a1 = a1 * r
            blinded_exponent_pairs.append((blinded_a0, blinded_a1))
            
        # 4. Compute the modular inverse and final blinding factor
        inverse_r_product = pow(r_product, -1, self.group.p - 1)
        final_blinding_factor = self.group.power(self.group.g, inverse_r_product)
        
        return (blinded_exponent_pairs, final_blinding_factor)