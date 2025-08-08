# src/crypto/commitment.py
import hashlib

class CommitmentScheme:
    """
    Implements a simple and secure hash-based commitment scheme.

    The purpose of this scheme is to allow a party (the sender) to commit
    to a value (a message) and reveal it later. The scheme ensures:
    1. Binding: The sender cannot change the message after committing to it.
    2. Hiding: The commitment does not reveal any information about the message.

    This uses H(key || message) as the commitment, where || denotes concatenation.
    """

    def __init__(self):
        pass

    def commit(self, message: bytes, key: bytes) -> bytes:
        """
        Creates a commitment to a message using a key.
        In the adaptive OT protocol, the 'message' is the sender's secret X_I,
        and the 'key' is the value K_I derived from the DDH synthesizer.
        """
        # We concatenate the key and message before hashing to ensure
        # that H(k, m) != H(m, k) in all cases.
        digest = hashlib.sha256(key + message).digest()
        return digest

    def verify(self, commitment: bytes, message: bytes, key: bytes) -> bool:
        """
        Verifies if a message and key match a given commitment.
        The receiver will use this method after the transfer phase to check
        if the sender's revealed message matches the commitment received during
        the setup phase.
        """
        # Re-compute the commitment using the revealed message and key
        expected_commitment = self.commit(message, key)

        # Check if the re-computed commitment matches the original one
        return commitment == expected_commitment