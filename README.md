Our working assumption is that block ciphers (such as DES or AES) or keyed one-way hash functions (such as HMAC), 
can be modeled as a pseudo-random function. Therefore, the function FK(x) can be implemented by 
keying a block cipher with the key K and encrypting x, or keying a hash function with K and applying it to x.
The evaluation of a pseudo-random function is therefore considerably more efficient than a typical public-key operation.

The main idea of the protocol is to use a small set of O(log N) keys and mask each input with a combination of a different subset of the keys. 

# Step 1: Compute combined_product = Π_j a_j^{i_j}·r_j
# Step 2: Compute g^{combined_product}
# Step 3: Raise to final_blinding_factor = g^{r^{-1}} => Final = (g^{r^{-1}})^{combined_product}
# Step 4: Hash to get K_I = H(Final)
# Step 5: Verify commit(Y_I, M, K_I)