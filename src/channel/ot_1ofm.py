# src/channel/ot_1ofm.py
from __future__ import annotations
from typing import List, Tuple, Callable
import math, secrets

from src.crypto.ddh_group import DDHGroup
from src.channel.ddh_ot import DDHOTSender, DDHOTReceiver
from src.crypto.prf import prf_labeled

def _i2osp(x: int, l: int) -> bytes:
    if x < 0 or x >= (1 << (8*l)):
        raise ValueError("integer too large")
    return x.to_bytes(l, "big")

def _os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))

class OT1ofmSender:
    """
    Sender for 1-out-of-m OT via Protocol 2.1 composed from ℓ = ceil(log2 m) OTs.
    Payload elements are Z_q scalars (non-zero), encoded to fixed q-bytes.

    API (intended usage in your run loop):
        svc = OT1ofmSender(group, payload, label=b"ROW" or b"COL")
        # publish svc.ciphertexts (one-time) to the receiver side (same process/closure is OK)
        # for j in [0..ℓ-1]: run a 1-out-of-2 OT carrying (seed_j^0, seed_j^1) with DDHOT*
        # receiver decrypts exactly one payload element using the ℓ seeds it obtained
    """

    def __init__(self, group: DDHGroup, payload: List[int], label: bytes = b"OT1OFM") -> None:
        self.group = group
        self._check_group_strict()

        if not payload or any((not isinstance(x, int)) for x in payload):
            raise ValueError("payload must be a non-empty list of ints")
        self.q = group.q
        for x in payload:
            # In our protocol, honest sender gives elements in Z_q^* (1..q-1)
            if not (1 <= x < self.q):
                raise ValueError("payload element not in Z_q^*")

        self.payload: List[int] = payload[:]           # immutable view
        self.m = len(payload)
        self.l = math.ceil(math.log2(self.m)) if self.m > 1 else 1
        self.q_bytes = (self.q.bit_length() + 7) // 8  # fixed encoding length for Z_q
        self.label = bytes(label)
        self.sid = secrets.token_bytes(16)             # per-service salt for domain-separation

        # Per-bit seeds (random) and per-bit DDH-OT senders
        self.seeds0: List[bytes] = [secrets.token_bytes(32) for _ in range(self.l)]
        self.seeds1: List[bytes] = [secrets.token_bytes(32) for _ in range(self.l)]
        self.ot2_senders: List[DDHOTSender] = [DDHOTSender(group) for _ in range(self.l)]

        # Precompute ciphertexts CT_t = M_t XOR (⊕_j PRF(seed_j^{bit_j(t)} || label || j || sid))
        self.ciphertexts: List[bytes] = []
        for t in range(self.m):
            bits = [(t >> j) & 1 for j in range(self.l)]
            pad = bytes([0]) * self.q_bytes
            for j, b in enumerate(bits):
                seed = self.seeds1[j] if b == 1 else self.seeds0[j]
                # Strong domain separation across direction/bit/index/session
                info = self.label + b"|j=" + _i2osp(j, 2) + b"|sid=" + self.sid
                pad = _xor_bytes(pad, prf_labeled(seed, info, self.q_bytes))
            mt = _i2osp(self.payload[t] % self.q, self.q_bytes)
            ct = _xor_bytes(mt, pad)
            self.ciphertexts.append(ct)

    # --- Helpers used by receiver side orchestration ---

    def get_bitpair(self, j: int) -> Tuple[bytes, bytes]:
        if not (0 <= j < self.l):
            raise IndexError("bit index out of range")
        return self.seeds0[j], self.seeds1[j]

    def get_ot2_sender(self, j: int) -> DDHOTSender:
        if not (0 <= j < self.l):
            raise IndexError("bit index out of range")
        return self.ot2_senders[j]

    def _check_group_strict(self) -> None:
        assert hasattr(self.group, "p") and hasattr(self.group, "q") and hasattr(self.group, "g")
        # g must have exact order q
        if pow(self.group.g, self.group.q, self.group.p) != 1 or pow(self.group.g, 2, self.group.p) == 1:
            raise AssertionError("Group generator g does not have exact order q")


class OT1ofmReceiver:
    """
    Receiver for 1-out-of-m OT via Protocol 2.1, using ℓ DDH-based 1-out-of-2 OTs.

    Usage pattern:
        R = OT1ofmReceiver(group, label=b"ROW")
        chosen_scalar = R.choose(index=i, service=svc)  # returns Z_q element from svc.payload[i]
    """

    def __init__(self, group: DDHGroup, label: bytes = b"OT1OFM") -> None:
        self.group = group
        self._check_group_strict()
        self.label = bytes(label)

    def choose(self, index: int, service: OT1ofmSender) -> int:
        m = service.m
        if not (0 <= index < m):
            raise IndexError("index out of range")

        l = service.l
        q = service.q
        q_bytes = service.q_bytes
        sid = service.sid

        # 1) Run ℓ times 1-out-of-2 OT to obtain the per-bit seed for our index
        seeds: List[bytes] = []
        for j in range(l):
            bit = (index >> j) & 1
            S2 = service.get_ot2_sender(j)             # sender's DDH OT for this bit
            r2 = DDHOTReceiver(self.group, bit)        # receiver with our choice bit
            B = r2.generate_B(S2.A)                    # S2.A = g^a
            m0, m1 = service.get_bitpair(j)
            c0, c1 = S2.respond(B, m0, m1)             # encrypted seed pair
            seed_j = r2.recover((c0, c1))              # recover our chosen seed_j^{bit}
            if len(seed_j) != 32:
                raise AssertionError("seed length mismatch")
            seeds.append(seed_j)

        # 2) Reconstruct the XOR-pad for our chosen index
        pad = bytes([0]) * q_bytes
        for j, seed in enumerate(seeds):
            info = self.label + b"|j=" + _i2osp(j, 2) + b"|sid=" + sid
            pad = _xor_bytes(pad, prf_labeled(seed, info, q_bytes))

        # 3) Decrypt the single ciphertext CT_index to obtain M_index
        ct = service.ciphertexts[index]
        if len(ct) != q_bytes:
            raise ValueError("ciphertext length mismatch")
        m_bytes = _xor_bytes(ct, pad)
        x = _os2ip(m_bytes)

        # Sanity: should be in Z_q^* as promised by the sender
        if not (1 <= x < q):
            # If you *must* be resilient, you could do x %= q and reject 0;
            # but honest sender produces 1..q-1 exactly.
            raise ValueError("decrypted value not in Z_q^*")
        return x

    def _check_group_strict(self) -> None:
        assert hasattr(self.group, "p") and hasattr(self.group, "q") and hasattr(self.group, "g")
        if pow(self.group.g, self.group.q, self.group.p) != 1 or pow(self.group.g, 2, self.group.p) == 1:
            raise AssertionError("Group generator g does not have exact order q")


def make_chooser(group: DDHGroup, label: bytes, service: OT1ofmSender) -> Callable[[List[int], int], int]:
    """
    Helper to build a chooser closure compatible with AdaptiveReceiver.select_and_open(...)
    signature: chooser(payload_list, index) -> int in Z_q^*

    We *ignore* the provided payload_list (we already have `service.payload`), but we
    keep the parameter for API compatibility. If you want extra paranoia, compare them.
    """
    R = OT1ofmReceiver(group, label)
    def chooser(_payload_list: List[int], idx: int) -> int:
        # sanity check:
        if _payload_list != service.payload:
            raise AssertionError("payload mismatch between parties")
        return R.choose(idx, service)
    return chooser