from __future__ import annotations

import argparse
from typing import Dict, List, Optional

from src.channel.ot_1of4 import OT1of4Receiver, OT1of4Sender
from src.crypto.ddh_group import DDHGroup


def _pack_bundle(values: List[Optional[bytes]]) -> bytes:
    """Encode [x0_or_bot, x1_or_bot, x2_or_bot] into bytes for OT payload."""
    if len(values) != 3:
        raise ValueError("bundle must have exactly 3 slots")

    out = bytearray()
    for v in values:
        if v is None:
            out.extend(b"\x00")
            continue

        out.extend(b"\x01")
        out.extend(len(v).to_bytes(4, "big"))
        out.extend(v)
    return bytes(out)


def _unpack_bundle(blob: bytes) -> List[Optional[bytes]]:
    """Decode bytes payload back to [x0_or_bot, x1_or_bot, x2_or_bot]."""
    idx = 0
    out: List[Optional[bytes]] = []

    for _ in range(3):
        if idx >= len(blob):
            raise ValueError("malformed bundle: unexpected end while reading flag")

        flag = blob[idx]
        idx += 1

        if flag == 0:
            out.append(None)
            continue

        if flag != 1:
            raise ValueError("malformed bundle: invalid slot flag")

        if idx + 4 > len(blob):
            raise ValueError("malformed bundle: truncated length field")
        ln = int.from_bytes(blob[idx:idx + 4], "big")
        idx += 4

        if idx + ln > len(blob):
            raise ValueError("malformed bundle: truncated data")
        out.append(blob[idx:idx + ln])
        idx += ln

    if idx != len(blob):
        raise ValueError("malformed bundle: trailing bytes")

    return out


def _fmt(v: Optional[bytes]) -> str:
    if v is None:
        return "BOT"
    return v.decode("utf-8", errors="replace")


def _mask_from_bundle(bundle: List[Optional[bytes]]) -> str:
    if len(bundle) != 3:
        raise ValueError("bundle must have exactly 3 slots")
    return "".join("1" if x is not None else "0" for x in bundle)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="4-party distribution via 1-out-of-4 OT bundles (semi-honest)."
    )
    parser.add_argument("--x0", type=str, default="x0", help="message x0")
    parser.add_argument("--x1", type=str, default="x1", help="message x1")
    parser.add_argument("--x2", type=str, default="x2", help="message x2")
    args = parser.parse_args()

    group = DDHGroup()
    messages: List[bytes] = [
        args.x0.encode("utf-8"),
        args.x1.encode("utf-8"),
        args.x2.encode("utf-8"),
    ]

    if len(messages) != 3:
        raise ValueError("messages must contain exactly 3 elements: x0, x1, x2")

    # 4 choices in OT1of4:
    # idx 0 -> S0 allocation: x0, x1, BOT
    # idx 1 -> S1 allocation: BOT, x1, x2
    # idx 2 -> S2 allocation: x0, BOT, x2
    # idx 3 -> unused dummy: BOT, BOT, BOT
    bundles: List[List[Optional[bytes]]] = [
        [messages[0], messages[1], None],
        [None, messages[1], messages[2]],
        [messages[0], None, messages[2]],
        [None, None, None],
    ]
    packed_bundles = [_pack_bundle(b) for b in bundles]

    receiver_choice: Dict[str, int] = {
        "S0": 0,
        "S1": 1,
        "S2": 2,
    }
    receiver_order = ["S0", "S1", "S2"]
    outputs: Dict[str, List[Optional[bytes]]] = {}

    total_ot_sessions = 0
    all_ok = True

    print("M holds:", [args.x0, args.x1, args.x2])
    print("Protocol: one OT1of4 bundle selection per receiver")
    print("Choice map:")
    print("  idx 0 -> [x0, x1, BOT]")
    print("  idx 1 -> [BOT, x1, x2]")
    print("  idx 2 -> [x0, BOT, x2]")
    print("  idx 3 -> [BOT, BOT, BOT] (dummy)")
    print()

    for receiver_name in receiver_order:
        choice_idx = receiver_choice[receiver_name]

        sender = OT1of4Sender(group, packed_bundles, label=b"4PARTY")
        receiver = OT1of4Receiver(group, label=b"4PARTY")
        recovered_blob = receiver.choose(choice_idx, sender)
        recovered_bundle = _unpack_bundle(recovered_blob)

        expected = bundles[choice_idx]
        ok = recovered_bundle == expected
        all_ok = all_ok and ok
        outputs[receiver_name] = recovered_bundle

        print(f"{receiver_name} selects idx={choice_idx}")
        print("  got     =", [_fmt(v) for v in recovered_bundle])
        print("  expect  =", [_fmt(v) for v in expected])
        print("  result  =", "OK" if ok else "MISMATCH")
        print()

        total_ot_sessions += 1

    print("Final distribution")
    for receiver_name in receiver_order:
        got = outputs[receiver_name]
        expected = bundles[receiver_choice[receiver_name]]
        receiver_ok = got == expected
        all_ok = all_ok and receiver_ok

        print(f"{receiver_name} mask={_mask_from_bundle(got)}")
        print("  got     =", [_fmt(v) for v in got])
        print("  expect  =", [_fmt(v) for v in expected])
        print("  result  =", "OK" if receiver_ok else "MISMATCH")
        print()

    print(f"Total OT sessions used: {total_ot_sessions}")
    if not all_ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
