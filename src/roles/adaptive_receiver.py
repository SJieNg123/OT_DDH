# src/roles/adaptive_receiver.py
import math
import hashlib
from src.crypto.ddh_group import DDHGroup
from src.crypto.commitment import CommitmentScheme
from channel.ddh_ot import OTChannel
from src.utils.bitops import int_to_bitlist

class AdaptiveReceiver:
    """
    Implements the Receiver's logic for the Adaptive OT Protocol (Protocol 3.2).

    The receiver stores the initial commitments from the sender. To retrieve
    a message, it engages in an interactive protocol to learn the specific
    key for that one message's commitment, without revealing its choice.
    """

    def __init__(self, N: int, crypto_group: DDHGroup):
        """
        Initializes the receiver.
        Args:
            N: The total number of messages the sender has.
            crypto_group: The DDHGroup instance agreed upon with the sender.
        """
        self.N = N
        self.l = int(math.log2(N))
        self.group = crypto_group
        self.commitment_scheme = CommitmentScheme()
        self.commitments: list[bytes] = []

    def receive_commitments(self, commitments: list[bytes]):
        """
        Stores the list of N commitments received from the sender during setup.
        """
        print(f"Receiver: Stored {len(commitments)} commitments from sender.")
        self.commitments = commitments

    def retrieve_item(
        self,
        choice_index: int,
        blinded_exponent_pairs: list[tuple[int, int]],
        final_blinding_factor: int,
        channel: OTChannel,
        original_message: bytes # For verification only
    ) -> bool:
        """
        Performs the Transfer phase of Protocol 3.2 to retrieve one item.
        Args:
            choice_index: The index of the message the receiver wants to learn.
            blinded_exponent_pairs: The blinded values from the sender for this transfer.
            final_blinding_factor: The final un-blinding value from the sender.
            channel: The 1-out-of-2 OT channel for the interactive part.
            original_message: The original plaintext message, passed here only
                              to allow the receiver to verify the final result.

        Returns:
            True if the message was successfully recovered and verified, False otherwise.
        """
        print(f"\nReceiver: Attempting to retrieve message at index {choice_index}...")
        
        # 1. For each j, use OT to get the correct blinded exponent a_j^i_j * r_j
        choice_bits = int_to_bitlist(choice_index, self.l)
        selected_blinded_exponents = []
        for j, bit in enumerate(choice_bits):
            # Use the ideal OT channel to get the chosen blinded exponent
            blinded_exp = channel.send(
                blinded_exponent_pairs[j][0],
                blinded_exponent_pairs[j][1],
                bit
            )
            selected_blinded_exponents.append(blinded_exp)

        # 2. Multiply the selected blinded exponents together
        # This results in (a1*a2*...*al) * (r1*r2*...*rl)
        combined_product = 1
        for exp in selected_blinded_exponents:
            combined_product *= exp

        # 3. Use the final_blinding_factor to "un-blind" the result.
        # final_blinding_factor is g^(1/(r1*...*rl))
        # We compute (g^(...))^(1/(...)) to cancel out the r values.
        # The reconstructed key K_I is h(g^(a1*...*al))
        reconstructed_synthesizer_output = self.group.power(
            final_blinding_factor,
            combined_product
        )
        reconstructed_key_K_I = hashlib.sha256(str(reconstructed_synthesizer_output).encode()).digest()
        
        print("Receiver: Reconstructed the commitment key.")

        # 4. Verify the reconstructed key against the commitment
        commitment_Y_I = self.commitments[choice_index]
        is_verified = self.commitment_scheme.verify(
            commitment_Y_I,
            original_message,
            reconstructed_key_K_I
        )
        
        return is_verified