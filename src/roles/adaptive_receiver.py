# src/roles/adaptive_receiver.py
import math
import hashlib
from src.crypto.ddh_group import DDHGroup
from src.crypto.commitment import CommitmentScheme
from src.utils.bitops import int_to_bitlist

class AdaptiveReceiver:
    def __init__(self, N: int, crypto_group: DDHGroup):
        self.N = N
        self.l = int(math.log2(N))
        self.group = crypto_group
        self.commitment_scheme = CommitmentScheme()
        self.commitments: list[bytes] = []
        # Expose int_to_bitlist for the runner script
        self.int_to_bitlist = int_to_bitlist

    def receive_commitments(self, commitments: list[bytes]):
        print(f"Receiver: Stored {len(commitments)} commitments from sender.")
        self.commitments = commitments

    def reconstruct_and_verify_key(
        self,
        choice_index: int,
        selected_blinded_exponents: list[int],
        final_blinding_factor: int,
        original_message: bytes # For verification only
    ) -> bool:
        # Multiply the selected blinded exponents together
        combined_product = 1
        for exp in selected_blinded_exponents:
            combined_product *= exp

        # Use the final_blinding_factor to "un-blind" the result.
        reconstructed_synthesizer_output = self.group.power(
            final_blinding_factor,
            combined_product
        )
        reconstructed_key_K_I = hashlib.sha256(str(reconstructed_synthesizer_output).encode()).digest()
        
        # Verify the reconstructed key against the commitment
        commitment_Y_I = self.commitments[choice_index]
        is_verified = self.commitment_scheme.verify(
            commitment_Y_I,
            original_message,
            reconstructed_key_K_I
        )
        return is_verified