# run_adaptive.py
from __future__ import annotations
import argparse
import random
from typing import List, Tuple

from src.crypto.ddh_group import DDHGroup
from src.roles.adaptive_sender import AdaptiveSender
from src.roles.adaptive_receiver import AdaptiveReceiver
from src.channel.ot_1ofm import OT1ofmSender, make_chooser

def build_messages(m: int) -> List[bytes]:
    """Build an m x m grid of distinct messages in row-major order."""
    msgs: List[bytes] = []
    for i in range(m):
        for j in range(m):
            # 固定長度或可變長度都可；承諾會按長度自動遮罩
            msgs.append(f"MSG(i={i},j={j})".encode("utf-8"))
    return msgs

def one_round_query(
    group: DDHGroup,
    sender: AdaptiveSender,
    receiver: AdaptiveReceiver,
    i: int,
    j: int,
) -> bytes:
    """
    Execute one adaptive OT round for index (i,j):
      - Sender prepares round payload (two OT payloads + g^{(rr)^{-1}})
      - Sender instantiates two 1-of-m OT services (ROW/COL)
      - Receiver runs two 1-of-m OTs via chooser closures and opens Y_{i,j}
    """
    # 1) Sender prepares per-round payload (fresh r_R, r_C)
    round_payload = sender.prepare_query_payload()

    # 2) Sender creates 1-of-m OT services for ROW and COL
    row_payload = list(round_payload["row_ot_payload"])
    col_payload = list(round_payload["col_ot_payload"])
    svc_row = OT1ofmSender(group, row_payload, label=b"ROW")
    svc_col = OT1ofmSender(group, col_payload, label=b"COL")

    # 3) Build chooser closures for receiver
    row_chooser = make_chooser(group, b"ROW", svc_row)
    col_chooser = make_chooser(group, b"COL", svc_col)

    # 4) Receiver selects (i,j) and opens Y_{i,j}
    X_ij = receiver.select_and_open(
        i, j, round_payload,
        row_chooser=row_chooser,
        col_chooser=col_chooser,
        aad=b"",               # use blank AAD in this implementation
    )
    return X_ij

def main():
    parser = argparse.ArgumentParser(description="DDH-based Adaptive OT (Protocol 3.1) demo runner")
    parser.add_argument("--m", type=int, default=4, help="grid dimension (N = m*m)")
    parser.add_argument("--rounds", type=int, default=5, help="number of adaptive queries to run")
    parser.add_argument("--seed", type=int, default=0, help="PRNG seed for index selection only")
    args = parser.parse_args()

    m = args.m
    if m <= 0:
        raise ValueError("m must be positive")
    N = m * m

    # --- Group setup (prime-order subgroup) ---
    group = DDHGroup()  # 你的 DDHGroup 內部要檢查 g 的 order == q

    # --- Messages and parties ---
    messages = build_messages(m)
    sender = AdaptiveSender(group, messages)
    receiver = AdaptiveReceiver(group)

    # --- One-time public setup (publish commitments + hash params) ---
    setup_blob = sender.public_setup()
    receiver.ingest_public_setup(setup_blob)

    # --- Run multiple adaptive queries ---
    rng = random.Random(args.seed)
    ok = True
    for r in range(args.rounds):
        i = rng.randrange(0, m)
        j = rng.randrange(0, m)

        X = one_round_query(group, sender, receiver, i, j)
        expect = messages[i * m + j]

        match = (X == expect)
        print(f"[round {r+1}] query (i={i}, j={j}) -> "
              f"{'OK' if match else 'MISMATCH'} ; X = {X!r}")
        if not match:
            ok = False

    if not ok:
        raise SystemExit(1)

if __name__ == "__main__":
    main()