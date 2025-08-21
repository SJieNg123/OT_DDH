# src/roles/adaptive_receiver.py
from __future__ import annotations
from typing import Callable, Dict, Any, List, Tuple
import secrets

from src.crypto.ddh_group import DDHGroup
from src.crypto.commitment import CommitmentScheme

class AdaptiveReceiver:
    """
    DDH-based adaptive OT receiver (Naor-Pinkas 2005, Protocol 3.1).
    This class assumes:
      - Sender has published a one-time public setup via AdaptiveSender.public_setup().
      - Each query round, sender provides:
          * row_ot_payload: [ (R_t * r_R) mod q ] for t in [0..m-1]
          * col_ot_payload: [ (C_t * r_C) mod q ] for t in [0..m-1]
          * g_pow_inv_rr  : g^{(r_R * r_C)^{-1}} in the prime-order subgroup
      - Receiver runs TWO 1-out-of-m OTs to obtain:
          * row_choice  := R_i * r_R (mod q)
          * col_choice  := C_j * r_C (mod q)
        then reconstructs g^{R_i C_j}, derives K_{i,j}, and opens Y_{i,j}.

    Notes on API:
      - We do not implement the 1-out-of-m OT here. Instead, you pass in two
        callable "choosers" that perform the OT interaction and return the
        selected scalar (in Z_q). Their signature is:
            chooser(payload_list: List[int], index: int) -> int
        The chooser MUST execute a *real* 1-out-of-m OT with the sender
        over the provided payload list (not a trivial local index read!).
    """

    def __init__(self, group: DDHGroup) -> None:
        self.group = group
        self._check_group_strict()

        # Populated by ingest_public_setup()
        self.m: int | None = None
        self.Y: List[List[bytes]] | None = None
        self.alpha: int | None = None
        self.beta: int | None = None
        self.lambda_bytes: int | None = None
        self.commit = CommitmentScheme()

        # For sanity checks against sender's published parameters
        self.pub_p: int | None = None
        self.pub_q: int | None = None

    # ---------- One-time ingestion of sender's public setup ----------

    def ingest_public_setup(self, setup: Dict[str, Any]) -> None:
        """
        Accept the sender's published setup.
        Expected 'setup' keys (exactly as AdaptiveSender.public_setup()):
          - "m": int
          - "commitments": List[List[bytes]]  (Y_{i,j})
          - "hash_params": {"alpha": int, "beta": int, "lambda_bytes": int}
          - "group_p": int
          - "group_q": int
        """
        try:
            m = int(setup["m"])
            commitments = setup["commitments"]
            hp = setup["hash_params"]
            alpha = int(hp["alpha"])
            beta = int(hp["beta"])
            lambda_bytes = int(hp["lambda_bytes"])
            pub_p = int(setup["group_p"])
            pub_q = int(setup["group_q"])
        except Exception as e:
            raise ValueError(f"Malformed public setup: {e}")

        if m <= 0 or not isinstance(commitments, list) or len(commitments) != m:
            raise ValueError("Invalid commitments grid")
        for row in commitments:
            if not isinstance(row, list) or len(row) != m:
                raise ValueError("Invalid commitments row")

        # Cross-check group parameters
        if pub_p != self.group.p:
            raise AssertionError("Group modulus p mismatch")
        if pub_q != getattr(self.group, "q", None):
            raise AssertionError("Subgroup order q mismatch")

        # Store
        self.m = m
        self.Y = commitments
        self.alpha = alpha
        self.beta = beta
        self.lambda_bytes = lambda_bytes
        self.pub_p = pub_p
        self.pub_q = pub_q

    # ---------- Per-query protocol (for one selected (i,j)) ----------

    def select_and_open(
        self,
        i: int,
        j: int,
        round_payload: Dict[str, Any],
        row_chooser: Callable[[List[int], int], int],
        col_chooser: Callable[[List[int], int], int],
        aad: bytes = b"",
    ) -> bytes:
        """
        Execute one adaptive OT query for cell (i,j).

        Args:
          i, j           : desired indices in [0..m-1]
          round_payload  : {
                              "row_ot_payload": List[int],  # Z_q elements
                              "col_ot_payload": List[int],  # Z_q elements
                              "g_pow_inv_rr"  : int         # group element
                           }
          row_chooser    : callable to run a 1-out-of-m OT over row payload
          col_chooser    : callable to run a 1-out-of-m OT over col payload
          aad            : optional associated data for commitment open()
                           (must match sender's commit-time aad; default b"")

        Returns:
          The plaintext X_{i,j} (bytes) recovered by opening Y_{i,j}.
        """
        self._ensure_setup_ready()

        m = self.m  # type: ignore
        q = self.pub_q  # type: ignore
        p = self.pub_p  # type: ignore

        if not (0 <= i < m and 0 <= j < m):
            raise IndexError("Index out of range")

        try:
            row_list: List[int] = list(round_payload["row_ot_payload"])
            col_list: List[int] = list(round_payload["col_ot_payload"])
            g_pow_inv_rr: int = int(round_payload["g_pow_inv_rr"])
        except Exception as e:
            raise ValueError(f"Malformed round payload: {e}")

        if len(row_list) != m or len(col_list) != m:
            raise ValueError("OT payload length mismatch")

        # Basic sanity: payload elements must be in Z_q (0..q-1); non-zero expected
        for x in row_list + col_list:
            if not (0 <= int(x) < q):  # allow 0 for defensive check; we reject below
                raise ValueError("OT payload element not in Z_q")
        if pow(g_pow_inv_rr, q, p) != 1:
            raise AssertionError("g_pow_inv_rr is not in the prime-order subgroup")

        # --- Run two 1-out-of-m OTs to obtain scalars in Z_q ---
        # IMPORTANT: these choosers MUST implement *real OT* with the sender.
        Ri_rR = row_chooser(row_list, i) % q
        Cj_rC = col_chooser(col_list, j) % q
        if Ri_rR == 0 or Cj_rC == 0:
            # With honest sender and r_R, r_C in Z_q^*, this cannot be 0.
            raise ValueError("Received zero scalar from OT; aborting")

        # --- Reconstruct g^{R_i C_j} ---
        # Compute exponent e := (Ri_rR * Cj_rC) mod q
        e = (Ri_rR * Cj_rC) % q
        # Then (g^{(r_R r_C)^{-1}})^e = g^{R_i C_j}  (all exponents in Z_q)
        g_pow_RiCj = pow(g_pow_inv_rr, e, p)

        # --- Derive K_{i,j} = h(g^{R_i C_j}) and open Y_{i,j} ---
        K_ij = self._h_pairwise_to_bytes(g_pow_RiCj)
        Y_ij = self.Y[i][j]  # type: ignore
        X_ij = self.commit.open(Y_ij, K_ij, aad=aad)
        return X_ij

    # ---------- Helpers ----------

    def _ensure_setup_ready(self) -> None:
        if self.m is None or self.Y is None:
            raise RuntimeError("Public setup not ingested")
        if self.alpha is None or self.beta is None or self.lambda_bytes is None:
            raise RuntimeError("Hash parameters not set")
        if self.pub_q is None or self.pub_p is None:
            raise RuntimeError("Group parameters not set")

    def _h_pairwise_to_bytes(self, g_elem: int) -> bytes:
        """
        Pairwise-independent hash h: G_g -> {0,1}^λ, consistent with sender:
            v := g_elem mod p
            v_mod_q := v mod q
            y := (alpha * v_mod_q + beta) mod q
            return I2OSP(y, lambda_bytes)
        """
        assert self.alpha is not None and self.beta is not None and self.lambda_bytes is not None
        q = self.pub_q  # type: ignore

        v = g_elem % self.group.p
        v_mod_q = v % q
        y = (self.alpha * v_mod_q + self.beta) % q
        return y.to_bytes(self.lambda_bytes, "big")

    def _check_group_strict(self) -> None:
        # Require prime-order subgroup on group
        assert hasattr(self.group, "p") and isinstance(self.group.p, int) and self.group.p > 2
        assert hasattr(self.group, "q") and isinstance(self.group.q, int) and self.group.q > 2, \
            "DDHGroup must expose prime order q of the subgroup"
        assert hasattr(self.group, "g") and isinstance(self.group.g, int)
        # Verify generator really has order q
        if pow(self.group.g, self.group.q, self.group.p) != 1 or pow(self.group.g, 2, self.group.p) == 1:
            raise AssertionError("Group generator g does not have exact order q")

    def _h_pairwise_to_bytes(self, g_elem: int) -> bytes:
        """
        Pairwise-independent hash h: G_g -> {0,1}^λ, consistent with sender:
        v := g_elem mod p
        y := (alpha * (v mod q) + beta) mod q
        return LSB_λbits(y) encoded in exactly lambda_bytes
        """
        assert self.alpha is not None and self.beta is not None and self.lambda_bytes is not None
        q = self.pub_q  # type: ignore

        v = g_elem % self.group.p
        v_mod_q = v % q
        y_full = (self.alpha * v_mod_q + self.beta) % q

        # --- NEW: same λ-bit truncation as sender ---
        mask_bits = 8 * self.lambda_bytes
        y_trunc = y_full & ((1 << mask_bits) - 1)
        return y_trunc.to_bytes(self.lambda_bytes, "big")