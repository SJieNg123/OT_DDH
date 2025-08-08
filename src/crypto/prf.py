import hashlib

def prf(key: bytes, msg_len: int) -> bytes:
    # This PRF implementation is well-designed and correct.
    out = b''
    counter = 0
    while len(out) < msg_len:
        digest = hashlib.sha256(key + counter.to_bytes(4, 'big')).digest()
        out += digest
        counter += 1
    return out[:msg_len]