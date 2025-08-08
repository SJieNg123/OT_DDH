import os

# xor operation on two byte strings
# Raises ValueError if lengths do not match
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Input lengths for xor_bytes must match.")
    return bytes(x ^ y for x, y in zip(a, b))

# Generate a random byte string of specified length
def random_bytes(length: int) -> bytes:
    return os.urandom(length)

# Convert a byte string back to an integer
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

# Pad a byte string to a specified length (right padding with 0)
def pad_bytes(b: bytes, length: int) -> bytes:
    if len(b) > length:
        raise ValueError("Cannot pad: input is longer than target length.")
    return b.ljust(length, b'\x00')

def int_to_bitlist(n: int, num_bits: int) -> list[int]:
    """Converts an integer to a list of its bits, padded to num_bits."""
    # {0:b} formats the number as binary
    # [2:] strips the '0b' prefix
    # .zfill(num_bits) pads with leading zeros to the desired length
    bit_string = format(n, 'b').zfill(num_bits)
    return [int(bit) for bit in bit_string]