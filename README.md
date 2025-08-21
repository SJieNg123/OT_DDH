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
- **Group**: safe prime p; prime-order subgroup of order q = (p-1)/2; generator g has exact order q. All exponents are in Z_q.
- **Pairwise-independent hash**: `h{α,β}(v)=(α(vmodq)+β)modq`, then truncate to λ bits to derive a key.
- **Decryptable commitment**: `Y = len(X)[4] || ( X ⊕ PRF(K,"PAD") ) || HMAC( PRF(K,"MAC"), len||aad||cipher ).`
- **OT building blocks**: 
  - 1-out-of-2 OT (Naor–Pinkas) in `channel/ddh_ot.py`.
  - 1-out-of-m OT in `channel/ot_1ofm.py` via `ℓ=⌈log{2} m⌉` independent 1-out-of-2 OTs.

### Main Steps
1. One-time setup (Sender)
- Sample `R[0..m-1], C[0..m-1] ∈ Z_q*`, hash params `alpha, beta, and lambda_bytes`.
- For each cell `(i,j)`: compute `dh = g^{R_i C_j}`, derive `K_ij = h_{alpha,beta}(dh)` then truncate to `lambda_bytes`, commit `Y_ij = commit(X[i][j], K_ij, aad=b"")`.
- Publish `{m, commitments=Y, hash_params={alpha,beta,lambda_bytes}, group_p=p, group_q=q}`.

2. Ingest setup (Receiver)
- Store `Y, alpha, beta, lambda_bytes, and (p,q)`; verify group matches.

3. Per-query payload (Sender)
- Sample fresh `r_R, r_C ∈ Z_q*`.
- Build `row_ot_payload = [ (R_t * r_R) mod q ], col_ot_payload = [ (C_t * r_C) mod q ]`.
- Compute `rr = (r_R * r_C) mod q, g_pow_inv_rr = g^{rr^{-1}}`.
- Send `{row_ot_payload, col_ot_payload, g_pow_inv_rr}`.

4. Row selection OT (Receiver)
- Run 1-of-m OT over `row_ot_payload` to obtain `Ri_rR ∈ Z_q*`.

5. Column selection OT (Receiver)
- Run 1-of-m OT over `col_ot_payload` to obtain `Cj_rC ∈ Z_q*`.

6. Reconstruct shared group element (Receiver)
- Check pow(g_pow_inv_rr, q, p) == 1.
- Compute `e = (Ri_rR * Cj_rC) mod q`, then `g_pow_RiCj = (g_pow_inv_rr)^e mod p` (which equals `g^{R_i C_j}`).

7. Derive key (Receiver)
- `K_ij = h_{alpha,beta}(g_pow_RiCj)` with λ-bit truncation to `lambda_bytes`.

8. Open commitment (Receiver)
- `X_ij = open(Y[i][j], K_ij, aad=b"" # or aad=f"r={i}&c={j}".encode())`.
- HMAC verify → output `X[i][j]`.

9. Repeat
- For each new query, repeat steps 3–8 with fresh `r_R, r_C`.

## Project Structure
```
OT_DDH/
├─ src/
│  ├─ channel/
│  │  ├─ ddh_ot.py        # 1-of-2 OT (Naor–Pinkas) with subgroup checks & domain separation
│  │  └─ ot_1ofm.py       # 1-of-m OT via ℓ × (1-of-2) + XOR of PRF pads
│  ├─ crypto/
│  │  ├─ ddh_group.py     # safe prime p, subgroup order q, generator g with exact order q
│  │  ├─ prf.py           # HMAC-SHA256 counter PRF: prf_labeled(...) / prf_msg(...)
│  │  └─ commitment.py    # decryptable commitment: PRF mask + HMAC tag
│  ├─ roles/
│  │  ├─ adaptive_sender.py
│  │  └─ adaptive_receiver.py
│  └─ utils/
│     └─ bitops.py        # fixed-length encoders, xor, etc.
└─ run_adaptive.py         # smoke test, remove it if not needed
```

## Requirements
- Python 3.8+
- No external dependencies (uses only standard library)

## Core Components
### roles/adaptive_sender.py
- Samples long-term secrets `R{i}` and `C{j}`, publishes commitments `Y{i,j}`.
- For each query, emits two 1-of-m OT payloads and `g^{r{R}r{C}}^-1`.

### roles/adaptive_receiver.py
- Runs two 1-of-m OTs to get `R{i}r{R}` and `C{j}r{C}`.
- Reconstructs `g^{R{i}C{j}}`, derives the key, and opens `Y{i,j}`.

### channel/ddh_ot.py (1-of-2 OT)
- Naor–Pinkas construction; subgroup check on B.
- Pads derived via `prf_labeled(k_bytes, b"OT2|m0/m1", len)` for domain separation.

### channel/ot_1ofm.py (1-of-m OT)
- ℓ=⌈log2 m⌉ 1-of-2 OTs produce bitwise seeds.
- Pad for index t: XOR of `prf_msg(seed_j, info=label|j|sid, q_bytes)`

### crypto/commitment.py
- Decryptable commitment with PRF mask + HMAC; rejects any tamper/wrong key/AAD.
- Keys derived from pairwise-independent hash with λ-bit truncation.