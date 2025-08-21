# src/roles/adaptive_sender.py
from __future__ import annotations
from typing import List, Tuple, Dict, Any
import math
import secrets

from src.crypto.ddh_group import DDHGroup
from src.crypto.commitment import CommitmentScheme

class AdaptiveSender:
    """
    DDH-based adaptive OT sender (Naor–Pinkas 2005, Protocol 3.1).
    Strict prime-order subgroup model.

    Setup (once):
      - Choose R_1..R_m, C_1..C_m in Z_q^*, where m = sqrt(N).
      - Publish commitments Y_{i,j} to messages X_{i,j} using keys
          K_{i,j} = h( g^(R_i * C_j) )
        where h is a pairwise-independent hash from G_g to {0,1}^λ.

    Each transfer (per selected cell (i,j)):
      - Sample fresh r_R, r_C in Z_q^*.
      - Run two 1-out-of-m OTs with payloads:
           row_msgs = [ (R_t * r_R) mod q ]_t
           col_msgs = [ (C_t * r_C) mod q ]_t
      - Send g_pow_inv_rr = g^{ (r_R * r_C)^{-1} }.
      - Receiver combines its two OT outputs and g_pow_inv_rr to recover
        g^{R_i C_j}, then derives K_{i,j} and opens Y_{i,j}.
    """

    def __init__(self, group: DDHGroup, messages: List[bytes]) -> None:
        self.group = group
        self._check_group_strict()

        self.N = len(messages)
        self.m = self._as_perfect_square(self.N)
        # reshape messages to m x m grid (row-major)
        self.X = [list(messages[r*self.m:(r+1)*self.m]) for r in range(self.m)]

        # Pairwise-independent hash parameters over Z_q
        # h_u(v) = (alpha * v + beta) mod q, output truncated to λ bits
        self.q = self.group.q  # prime order
        self.alpha = self._rand_nonzero_scalar()
        self.beta = secrets.randbelow(self.q)  # can be 0..q-1

        # Key size λ ≈ |G|/2 bits -> λ_bytes = floor(log2(q)/2)/8
        self.lambda_bytes = max(16, (self.q.bit_length() // 2 + 7) // 8)

        # Long-term row/column scalars in Z_q^*
        self.R: List[int] = [self._rand_nonzero_scalar() for _ in range(self.m)]
        self.C: List[int] = [self._rand_nonzero_scalar() for _ in range(self.m)]

        # Precompute commitments Y_{i,j}
        self.commit = CommitmentScheme()
        self.Y: List[List[bytes]] = self._precompute_commitments()

    # ---------- Public API ----------

    def public_setup(self) -> Dict[str, Any]:
        """
        Data to publish once at initialization time.

        Returns:
          {
            "m": int,                          # grid dimension
            "commitments": List[List[bytes]],  # Y_{i,j}
            "hash_params": { "alpha": int, "beta": int, "lambda_bytes": int },
            "group_p": int,                    # optional sanity for receiver
            "group_q": int
          }
        """
        return {
            "m": self.m,
            "commitments": self.Y,
            "hash_params": {
                "alpha": int(self.alpha),
                "beta": int(self.beta),
                "lambda_bytes": int(self.lambda_bytes),
            },
            "group_p": int(self.group.p),
            "group_q": int(self.group.q),
        }

    def prepare_query_payload(self) -> Dict[str, Any]:
        """
        Prepare one-round payloads for the receiver's selected (i,j).

        Sender-side outputs (to be sent to receiver):
          - row_ot_payload : list[int] of length m   (Z_q elements)
          - col_ot_payload : list[int] of length m   (Z_q elements)
          - g_pow_inv_rr   : int (group element in Z_p^*)

        The receiver will run two 1-out-of-m OTs over these scalar lists,
        and then use g_pow_inv_rr to reconstruct g^{R_i C_j}.
        """
        r_R = self._rand_nonzero_scalar()
        r_C = self._rand_nonzero_scalar()

        row_payload = [(R_i * r_R) % self.q for R_i in self.R]
        col_payload = [(C_j * r_C) % self.q for C_j in self.C]

        rr = (r_R * r_C) % self.q
        inv_rr = self._inv_mod_q(rr)
        # g^{(r_R r_C)^{-1}} \in G_g
        g_pow_inv_rr = self.group.power(self.group.g, inv_rr)

        return {
            "row_ot_payload": row_payload,
            "col_ot_payload": col_payload,
            "g_pow_inv_rr": g_pow_inv_rr,
        }

    # ---------- Internals ----------

    def _precompute_commitments(self) -> List[List[bytes]]:
        """
        Compute all K_{i,j} = h( g^{R_i C_j} ) and Y_{i,j} = Commit_K(X_{i,j}).
        We implement g^{R_i C_j} efficiently as (g^{R_i})^{C_j}.
        """
        m, q, p, g = self.m, self.q, self.group.p, self.group.g

        # precompute g^{R_i}
        g_pow_R = [self.group.power(g, R_i) for R_i in self.R]

        Y: List[List[bytes]] = []
        for i in range(m):
            row_Y: List[bytes] = []
            for j in range(m):
                # g^{R_i C_j} = (g^{R_i})^{C_j}
                dh_elem = self.group.power(g_pow_R[i], self.C[j])
                K_ij = self._h_pairwise_to_bytes(dh_elem)
                Y_ij = self.commit.commit(self.X[i][j], K_ij)
                row_Y.append(Y_ij)
            Y.append(row_Y)
        return Y

    def _h_pairwise_to_bytes(self, g_elem: int) -> bytes:
        """
        Pairwise-independent hash h: G_g -> {0,1}^λ implemented as:
            v := enc(g_elem) as integer in [1, p-1] reduced mod q
            y := (alpha * v + beta) mod q
            return I2OSP(y, lambda_bytes)
        """
        v = g_elem % self.group.p
        # Map to Z_q to respect subgroup size in leftover hashing
        v_mod_q = v % self.q
        y = (self.alpha * v_mod_q + self.beta) % self.q
        return y.to_bytes(self.lambda_bytes, "big")

    # ---------- Strictness & helpers ----------

    def _check_group_strict(self) -> None:
        # Require prime-order subgroup data on the group
        assert hasattr(self.group, "p") and isinstance(self.group.p, int) and self.group.p > 2
        assert hasattr(self.group, "q") and isinstance(self.group.q, int) and self.group.q > 2, \
            "DDHGroup must expose prime order q of the subgroup"
        assert hasattr(self.group, "g") and isinstance(self.group.g, int)
        # Verify generator really has order q
        if pow(self.group.g, self.group.q, self.group.p) != 1 or pow(self.group.g, 2, self.group.p) == 1:
            raise AssertionError("Group generator g does not have exact order q")

    def _as_perfect_square(self, N: int) -> int:
        r = int(math.isqrt(N))
        if r * r != N:
            raise ValueError(f"N must be a perfect square; got {N}")
        return r

    def _rand_nonzero_scalar(self) -> int:
        # Sample uniformly from Z_q^* = {1..q-1}
        return secrets.randbelow(self.q - 1) + 1

    def _inv_mod_q(self, x: int) -> int:
        if x % self.q == 0:
            raise ValueError("inverse of 0 mod q")
        # Fermat since q is prime
        return pow(x, self.q - 2, self.q)
    
    def _h_pairwise_to_bytes(self, g_elem: int) -> bytes:
        """
        Pairwise-independent hash h: G_g -> {0,1}^λ implemented as:
        v := enc(g_elem) as integer in [1, p-1] reduced mod q
        y := (alpha * v + beta) mod q
        return LSB_λbits(y) encoded in exactly lambda_bytes
        """
        v = g_elem % self.group.p
        v_mod_q = v % self.q
        y_full = (self.alpha * v_mod_q + self.beta) % self.q

        # --- NEW: truncate to λ bits before to_bytes to avoid overflow ---
        mask_bits = 8 * self.lambda_bytes
        y_trunc = y_full & ((1 << mask_bits) - 1)
        return y_trunc.to_bytes(self.lambda_bytes, "big")