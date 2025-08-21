# src/crypto/commitment.py
import hmac
import hashlib
import struct
from typing import Optional

from src.crypto.prf import prf_labeled  # PRF(key_bytes: bytes, out_len: int) -> bytes

class CommitmentScheme:
    """
    Naor-Pinkas (2005) Protocol 3.1-style commitment:
      - Key K is a *bitstring* derived upstream as K = h(g^{R_i C_j}),
        where h is a pairwise independent hash from G_g to {0,1}^{|G_g|/2}.
      - commit_K(X) publishes a *decryptable ciphertext* Y, not a mere hash.
      - open_K(Y) deterministically recovers X from Y and K.

    Encoding (big-endian):
      Y = len(X)[4 bytes] || CIPHERTEXT || TAG(32 bytes)
      where:
        pad      = PRF(K || "NP05-COMMIT-PAD", len(X))
        CIPHERTEXT = X XOR pad
        mac_key  = PRF(K || "NP05-COMMIT-MAC", 32)
        TAG      = HMAC-SHA256(mac_key, len||aad||CIPHERTEXT)

    This gives:
      - Hiding: without K, CIPHERTEXT is a PRF-masked one-time pad.
      - Binding/Integrity: HMAC prevents malleability and binds to aad.
    """

    PAD_LABEL = b"NP05-COMMIT-PAD"
    MAC_LABEL = b"NP05-COMMIT-MAC"
    TAG_LEN = 32
    LEN_HDR = 4  # uint32 big-endian

    @staticmethod
    def _derive_pad(key: bytes, msg_len: int) -> bytes:
        return prf_labeled(key, CommitmentScheme.PAD_LABEL, msg_len)

    @staticmethod
    def _derive_mac_key(key: bytes) -> bytes:
        return prf_labeled(key, CommitmentScheme.MAC_LABEL, CommitmentScheme.TAG_LEN)

    def commit(self, message: bytes, key: bytes, aad: bytes = b"") -> bytes:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise TypeError("key must be non-empty bytes")
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes")

        m = bytes(message)
        hdr = struct.pack(">I", len(m))  # length prefix
        pad = self._derive_pad(key, len(m))
        ct = bytes(x ^ y for x, y in zip(m, pad))

        mac_key = self._derive_mac_key(key)
        tag = hmac.new(mac_key, hdr + aad + ct, hashlib.sha256).digest()
        return hdr + ct + tag

    def open(self, blob: bytes, key: bytes, aad: bytes = b"") -> bytes:
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < self.LEN_HDR + self.TAG_LEN:
            raise ValueError("invalid commitment blob")
        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise TypeError("key must be non-empty bytes")
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes")

        hdr = blob[: self.LEN_HDR]
        (mlen,) = struct.unpack(">I", hdr)
        ct = blob[self.LEN_HDR : -self.TAG_LEN]
        tag = blob[-self.TAG_LEN :]

        if len(ct) != mlen:
            raise ValueError("length/header mismatch")

        mac_key = self._derive_mac_key(key)
        exp_tag = hmac.new(mac_key, hdr + aad + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(exp_tag, tag):
            raise ValueError("invalid tag or wrong key/aad")

        pad = self._derive_pad(key, mlen)
        msg = bytes(x ^ y for x, y in zip(ct, pad))
        return msg

    def verify(self, blob: bytes, key: bytes, aad: bytes = b"", expected: Optional[bytes] = None) -> bool:
        """
        Verify integrity; optionally check that opening equals `expected`.
        """
        try:
            msg = self.open(blob, key, aad)
            return True if expected is None else (msg == expected)
        except Exception:
            return False