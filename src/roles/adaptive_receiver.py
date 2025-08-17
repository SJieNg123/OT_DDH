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
        
        # Check number of exponents
        assert len(selected_blinded_exponents) == self.l, (
            f"Expected {self.l} exponents, got {len(selected_blinded_exponents)}"
        )

        # Output bitlist according to index choosen
        bitlist = self.int_to_bitlist(choice_index, self.l)
        print(f"[DEBUG] Receiver bitlist for index {choice_index}: {bitlist}")

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

        # print(f"[DEBUG] Selected blinded exponents (a_j^0 or a_j^1): {[hex(e) for e in selected_blinded_exponents]}")
        # print(f"[DEBUG] Product of exponents: {combined_product}")
        # print(f"[DEBUG] final_blinding_factor: {hex(final_blinding_factor)}")
        # print(f"[DEBUG] synthesizer_output: {hex(reconstructed_synthesizer_output)}")
        print(f"[DEBUG] K_I: {reconstructed_key_K_I.hex()}")
        print(f"[DEBUG] Y_I: {commitment_Y_I.hex()}")
        print(f"[DEBUG] H(K, M): {self.commitment_scheme.commit(original_message, reconstructed_key_K_I).hex()}")

        return is_verified
