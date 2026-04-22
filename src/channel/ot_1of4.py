from __future__ import annotations

from typing import List, Tuple
import secrets

from src.channel.ddh_ot import DDHOTReceiver, DDHOTSender
from src.crypto.ddh_group import DDHGroup
from src.crypto.prf import prf_labeled


def _i2osp(x: int, l: int) -> bytes:
    if x < 0 or x >= (1 << (8 * l)):
        raise ValueError("integer too large")
    return x.to_bytes(l, "big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def _idx_to_bits(idx: int) -> Tuple[int, int]:
    if not (0 <= idx < 4):
        raise IndexError("index out of range for 1-of-4 OT")
    # Bit order: (b0, b1), where b0 is LSB.
    return idx & 1, (idx >> 1) & 1


def _build_info(label: bytes, sid: bytes, bit_pos: int) -> bytes:
    return label + b"|bit=" + _i2osp(bit_pos, 1) + b"|sid=" + sid


class OT1of4Sender:
    """
    Sender for 1-out-of-4 OT built from two independent 1-out-of-2 DDH OTs.

    Messages are indexed by 2-bit choices:
      index 0 -> (b1b0)=00
      index 1 -> (b1b0)=01
      index 2 -> (b1b0)=10
      index 3 -> (b1b0)=11
    """

    def __init__(self, group: DDHGroup, messages: List[bytes], label: bytes = b"OT1OF4") -> None:
        self.group = group
        self._check_group_strict()

        if len(messages) != 4:
            raise ValueError("messages must contain exactly 4 items")
        if not all(isinstance(m, (bytes, bytearray)) for m in messages):
            raise ValueError("all messages must be bytes-like")

        self.label = bytes(label)
        self.sid = secrets.token_bytes(16)
        self.messages: List[bytes] = [bytes(m) for m in messages]

        # For each bit position j in {0,1}, we prepare (seed_j^0, seed_j^1).
        self.seed_pairs: List[Tuple[bytes, bytes]] = [
            (secrets.token_bytes(32), secrets.token_bytes(32)),
            (secrets.token_bytes(32), secrets.token_bytes(32)),
        ]

        # Two independent 1-out-of-2 OTs, one per index bit.
        self.ot2_senders: List[DDHOTSender] = [DDHOTSender(group), DDHOTSender(group)]

        # Ciphertexts: CT_idx = M_idx XOR PRF(seed_0^{b0}) XOR PRF(seed_1^{b1})
        self.ciphertexts: List[bytes] = []
        for idx, msg in enumerate(self.messages):
            b0, b1 = _idx_to_bits(idx)
            pad0 = prf_labeled(self.seed_pairs[0][b0], _build_info(self.label, self.sid, 0), len(msg))
            pad1 = prf_labeled(self.seed_pairs[1][b1], _build_info(self.label, self.sid, 1), len(msg))
            ct = _xor_bytes(msg, _xor_bytes(pad0, pad1))
            self.ciphertexts.append(ct)

    def get_bitpair(self, bit_pos: int) -> Tuple[bytes, bytes]:
        if bit_pos not in (0, 1):
            raise IndexError("bit position must be 0 or 1")
        return self.seed_pairs[bit_pos]

    def get_ot2_sender(self, bit_pos: int) -> DDHOTSender:
        if bit_pos not in (0, 1):
            raise IndexError("bit position must be 0 or 1")
        return self.ot2_senders[bit_pos]

    def _check_group_strict(self) -> None:
        assert hasattr(self.group, "p") and hasattr(self.group, "q") and hasattr(self.group, "g")
        if pow(self.group.g, self.group.q, self.group.p) != 1 or pow(self.group.g, 2, self.group.p) == 1:
            raise AssertionError("Group generator g does not have exact order q")


class OT1of4Receiver:
    """
    Receiver for 1-out-of-4 OT using two DDH-based 1-out-of-2 OT executions.

    Usage pattern:
        recv = OT1of4Receiver(group)
        chosen_msg = recv.choose(index=2, service=svc)
    """

    def __init__(self, group: DDHGroup, label: bytes = b"OT1OF4") -> None:
        self.group = group
        self._check_group_strict()
        self.label = bytes(label)

    def choose(self, index: int, service: OT1of4Sender) -> bytes:
        b0, b1 = _idx_to_bits(index)
        if service.label != self.label:
            raise AssertionError("label mismatch between receiver and sender service")

        chosen_seeds: List[bytes] = []
        for bit_pos, bit in enumerate((b0, b1)):
            S2 = service.get_ot2_sender(bit_pos)
            R2 = DDHOTReceiver(self.group, bit)

            B = R2.generate_B(S2.A)
            m0, m1 = service.get_bitpair(bit_pos)
            c0, c1 = S2.respond(B, m0, m1)

            seed = R2.recover((c0, c1))
            if len(seed) != 32:
                raise AssertionError("seed length mismatch")
            chosen_seeds.append(seed)

        ct = service.ciphertexts[index]
        pad0 = prf_labeled(chosen_seeds[0], _build_info(self.label, service.sid, 0), len(ct))
        pad1 = prf_labeled(chosen_seeds[1], _build_info(self.label, service.sid, 1), len(ct))
        return _xor_bytes(ct, _xor_bytes(pad0, pad1))

    def _check_group_strict(self) -> None:
        assert hasattr(self.group, "p") and hasattr(self.group, "q") and hasattr(self.group, "g")
        if pow(self.group.g, self.group.q, self.group.p) != 1 or pow(self.group.g, 2, self.group.p) == 1:
            raise AssertionError("Group generator g does not have exact order q")
