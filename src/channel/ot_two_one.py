import math
from ..roles.sender import OTSender
from ..roles.receiver import OTReceiver

# channel/ot_two_one.py

class OTChannel:
    def __init__(self):
        # The channel does not need to maintain any state.
        pass

    def send(self, m0: bytes, m1: bytes, choice_bit: int) -> bytes:
        # Simulates the transfer of one of two messages.

        # Args:
        #    m0: The first message (corresponding to choice bit 0).
        #    m1: The second message (corresponding to choice bit 1).
        #    choice_bit: The receiver's choice (must be 0 or 1).

        # Returns: The message corresponding to the choice_bit.

        # Raises: ValueError: If the choice_bit is not 0 or 1.

        if choice_bit == 0:
            return m0
        elif choice_bit == 1:
            return m1
        else:
            raise ValueError("Choice bit must be 0 or 1.")

# This module implements the 1-out-of-n Oblivious Transfer (OT) protocol
def run_ot_1outofn_protocol(messages: list[bytes], choice_index: int) -> bytes:
    N = len(messages)
    assert N > 0 and (N & (N - 1)) == 0, "Number of messages must be a power of 2."
    l = int(math.log2(N))

    # Sender generates l key pairs and computes encrypted messages
    sender = OTSender(messages)
    key_pairs = sender.generate_key_pairs(l)  # [(K1^0, K1^1), ..., (Kl^0, Kl^1)]
    encrypted_db = sender.compute_masked_messages(key_pairs)

    # Step 2: Receiver obtains its corresponding keys via OT
    channel = OTChannel()
    receiver = OTReceiver(choice_index, l)
    receiver.obtain_keys_via_ot(key_pairs, channel)

    # Step 3: Sender sends all Yi to Receiver (already done in encrypted_db)
    # Step 4: Receiver uses its keys to recover X_I
    recovered = receiver.recover_message(encrypted_db)

    return recovered
