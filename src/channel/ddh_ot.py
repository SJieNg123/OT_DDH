# channel/ddh_ot.py
import secrets
import hashlib
from src.crypto.ddh_group import DDHGroup
from src.crypto.prf import prf

class DDHOTSender:
    def __init__(self, group: DDHGroup):
        self.group = group

    def prepare(self):
        # Generate random exponent a and public key A = g^a
        self.a = self.group.get_random_exponent()
        self.A = self.group.power(self.group.g, self.a)
        return self.A

    def respond(self, B: int, m0: bytes, m1: bytes) -> tuple[bytes, bytes]:
        # Validate public key B
        if not (1 < B < self.group.p):
            raise ValueError("Invalid public key B")

        # Validate message lengths
        if len(m0) != len(m1):
            raise ValueError("Messages must be of the same length")
        
        # Compute shared secrets
        K0 = self.group.power(B, self.a)  # K0 = B^a
        
        # Modular inverse for B/A
        A_inv = pow(self.A, -1, self.group.p)
        B_div_A = (B * A_inv) % self.group.p
        K1 = self.group.power(B_div_A, self.a)  # K1 = (B/A)^a

        # Derive pads via PRF
        # The key should be a consistent byte length
        key_byte_len = (self.group.p.bit_length() + 7) // 8
        pad0 = prf(K0.to_bytes(key_byte_len, 'big'), len(m0))
        pad1 = prf(K1.to_bytes(key_byte_len, 'big'), len(m1))

        # Mask messages
        c0 = bytes(x ^ y for x, y in zip(m0, pad0))
        c1 = bytes(x ^ y for x, y in zip(m1, pad1))

        return c0, c1

class DDHOTReceiver:
    def __init__(self, group: DDHGroup, choice_bit: int):
        self.group = group
        self.choice_bit = choice_bit
        
        # Generate the receiver's secret exponent 'b' during initialization
        self.b = self.group.get_random_exponent()
        self.A = None # To be received from sender

    def generate_B(self, A: int) -> int:
        self.A = A
        if self.choice_bit == 0:
            # If choice is 0, B = g^b
            return self.group.power(self.group.g, self.b)
        else: # choice_bit == 1
            # If choice is 1, B = A * g^b
            # This is the corrected logic
            g_pow_b = self.group.power(self.group.g, self.b)
            return (A * g_pow_b) % self.group.p

    def recover(self, c_tuple: tuple[bytes, bytes]) -> bytes:
        # Receiver always computes the key K as A^b
        K = self.group.power(self.A, self.b)
        
        # Choose the correct ciphertext
        chosen_ciphertext = c_tuple[self.choice_bit]

        # Derive the pad using the computed key K
        key_byte_len = (self.group.p.bit_length() + 7) // 8
        pad = prf(K.to_bytes(key_byte_len, 'big'), len(chosen_ciphertext))
        
        # Unmask the message
        return bytes(x ^ y for x, y in zip(chosen_ciphertext, pad))