# OT_DDH

Lightweight Python demos for DDH-based Oblivious Transfer (OT).

This repo includes:
- 1-out-of-2 OT
- 1-out-of-m OT (built from multiple 1-out-of-2 OTs)
- 1-out-of-4 OT (built from two 1-out-of-2 OTs)
- adaptive 1-out-of-N example flow
- 4-party bundle distribution demo

## Paper (brief)

The implementation is inspired by Naor-Pinkas OT work:
- Computationally Secure Oblivious Transfer
- CRYPTO 1999 / Journal of Cryptology 2005
- DOI: 10.1007/s00145-004-0102-6

This README keeps only practical usage notes. See source files for details.

## Requirements

- Python 3.8+
- Standard library only (no third-party dependency)

## Quick Start

From the repo root:

```powershell
python run_adaptive.py
python run_4party.py
```

Optional custom messages for 4-party demo:

```powershell
python run_4party.py --x0 A --x1 B --x2 C
```

## Demos

1. run_adaptive.py
- Adaptive OT demo over an m x m message grid.
- Uses sender/receiver roles and two 1-of-m OTs per query.

2. run_4party.py
- 4-party distribution example using OT1of4 bundles.
- Target outputs:
  - S0 gets [x0, x1, BOT]
  - S1 gets [BOT, x1, x2]
  - S2 gets [x0, BOT, x2]

## Project Structure

```text
OT_DDH/
├─ run_adaptive.py
├─ run_4party.py
└─ src/
   ├─ channel/
   │  ├─ ddh_ot.py      # 1-out-of-2 OT
   │  ├─ ot_1ofm.py     # 1-out-of-m OT
   │  └─ ot_1of4.py     # 1-out-of-4 OT
   ├─ crypto/
   │  ├─ ddh_group.py
   │  ├─ prf.py
   │  └─ commitment.py
   ├─ roles/
   │  ├─ adaptive_sender.py
   │  └─ adaptive_receiver.py
   └─ utils/
      └─ bitops.py
```

## Security Model Note

- Current demos assume semi-honest behavior.
- These scripts are for learning and prototyping, not production deployment.
