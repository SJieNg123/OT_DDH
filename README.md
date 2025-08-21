# 1-out-of-N Oblivious Transfer Protocol
A Python implementation of adaptive 1-out-of-N OT based on the paper Computationally Secure Oblivious Transfer (Naor & Pinkas, Journal of Cryptology 2005; CRYPTO’99). The receiver learns exactly one message out of N without revealing which one; the sender learns nothing about the choice.

## Paper Reference
This implementation is based on:
**"Computationally Secure Oblivious Transfer"**
- **Authors**: Moni Naor (Weizmann Institute), Benny Pinkas (HP Labs)
- **Published**: Journal of Cryptology, 2005 (originally appeared in CRYPTO '99)
- **DOI**: 10.1007/s00145-004-0102-6
- **Communicated by**: Joan Feigenbaum
The paper introduces efficient protocols for 1-out-of-n oblivious transfer based on the Decisional Diffie-Hellman assumption and provides the theoretical foundation for this implementation.

## Protocol Summary
### Parties
- **Sender** holds **N = m² messages** arranged in an `m × m` grid.
- **Receiver** wants `X[i][j]` and must reveal nothing about `(i, j)`

### Primitives & Keys
- **Group:** safe prime \(p\); **prime-order subgroup** of order \(q=(p-1)/2\); generator \(g\) has exact order \(q\). All exponents are in \(\mathbb{Z}_q^\*\).
- **Pairwise-independent hash:** \(h_{\alpha,\beta}(v)=(\alpha (v \bmod q)+\beta)\bmod q\), then **truncate to \(\lambda\) bits** to derive a key.
- **Decryptable commitment:**  
  `Y = len(X)[4] || ( X ⊕ PRF(K,"PAD") ) || HMAC( PRF(K,"MAC"), len||aad||cipher )`.
- **OT building blocks:**  
  - **1-out-of-2 OT** (Naor–Pinkas) in `channel/ddh_ot.py`.  
  - **1-out-of-m OT** in `channel/ot_1ofm.py` via \(\ell=\lceil\log_2 m\rceil\) independent 1-out-of-2 OTs.

### Flow
1. **Public setup (once):**  
   Sample \(R_i,C_j \in \mathbb{Z}_q^\*\). For each \((i,j)\): compute \(g^{R_i C_j}\), derive \(K_{i,j}=h(g^{R_i C_j})\), and publish commitment \(Y_{i,j}\). Also publish \((p,q,g)\) and \((\alpha,\beta,\lambda)\).
2. **Per-query transfer:**  
   Sample fresh \(r_R,r_C\in \mathbb{Z}_q^\*\). Provide two 1-of-m OTs with payloads \(\{R_t r_R \bmod q\}\) and \(\{C_t r_C \bmod q\}\), plus the group element \(g^{(r_R r_C)^{-1}}\).
3. **Receiver:**  
   Learn \(R_i r_R\) and \(C_j r_C\) via the two 1-of-m OTs, then compute
   \[
     g^{R_i C_j} = \big(g^{(r_R r_C)^{-1}}\big)^{(R_i r_R)(C_j r_C)} .
   \]
   Derive \(K_{i,j}\) and `open(Y_{i,j})` to obtain \(X[i][j]\).  
   *(Optional hardening: bind commitments to coordinates via AAD, e.g., `aad=b"r=i&c=j"` on both sides.)*

---

### Key Concepts
- **Commitment Scheme**: Used to commit messages to prevent tampering and enforce consistency.
- **Pairwise-Independent Hash**: Used to derive keys from DDH shared secrets for each message.
- **1-out-of-m OT**: The main building block for row and column selection.

### Main Steps

1. **Public Setup**:
   - Sender publishes:
     - A list of commitments `Y[i][j]` for each message `X[i][j]`
     - Hash parameters
     - Group parameters `(p, q, g)`

2. **Transfer Phase**:
   - Sender samples fresh `(r_R, r_C)` and generates OT payloads:
     - Row scalars: `[R_t * r_R mod q]`
     - Col scalars: `[C_t * r_C mod q]`
   - Sends `g^{(r_R * r_C)^{-1}}` to allow reconstruction of `g^{R_i C_j}`.

3. **Receiver**:
   - Participates in two **1-out-of-m OT** to learn:
     - `R_i * r_R` from row OT
     - `C_j * r_C` from column OT
   - Computes `g^{R_i C_j}` via:
     ```
     g^{(R_i * r_R)(C_j * r_C) * inv(r_R * r_C)} = g^{R_i C_j}
     ```
   - Derives key from hash and opens the commitment.

---

## Project Structure
```
OT_DDH/
├─ src/
│  ├─ channel/
│  │  ├─ ddh_ot.py
│  │  └─ ot_1ofm.py
│  ├─ crypto/
│  │  ├─ commitment.py
│  │  ├─ ddh_group.py
│  │  └─ prf.py
│  ├─ roles/
│  │  ├─ adaptive_receiver.py
│  │  └─ adaptive_sender.py
│  └─ utils/
│     └─ bitops.py
├─ README.md
└─ run_adaptive.py
```

## Requirements
- Python 3.8+
- No external dependencies (uses only standard library)

## Core Components
### AdaptiveSender (adaptive_sender.py)
- Samples long-term secrets R and C
- Publishes commitments to messages via DDH-derived keys
- Prepares OT payloads and g_pow_inv_rr for each transfer

### AdaptiveReceiver (adaptive_receiver.py)
- Selects (i, j) and participates in two 1-out-of-m OTs
- Reconstructs g^{R_i C_j}, hashes it to get key, and opens commitment

### DDHOTChannel (ddh_ot.py)
- Simulates two independent 1-out-of-m OTs over Z_q using ideal abstraction
- In a real implementation, replace with DDH-based OT