# run_adaptive_ot.py
from src.crypto.ddh_group import DDHGroup
from src.roles.adaptive_sender import AdaptiveSender
from src.roles.adaptive_receiver import AdaptiveReceiver

# We will use your new cryptographic channel.
# Note: The channel itself is stateless, but we will create new instances
# of the sender/receiver roles within it for each 1-out-of-2 OT.
from src.channel.ddh_ot import DDHOTSender, DDHOTReceiver

def perform_one_transfer(
    choice_index: int,
    sender: AdaptiveSender,
    receiver: AdaptiveReceiver,
    original_messages: list[bytes]
) -> bool:
    """
    Orchestrates a single, secure transfer of one message.
    """
    print(f"\n--- Starting Transfer for Index {choice_index} ---")
    
    # 1. Sender prepares the blinded values for this specific transfer
    blinded_pairs, final_blinding_factor = sender.prepare_transfer_values()

    # 2. Receiver gets the blinded exponents via l separate 1-out-of-2 OTs
    choice_bits = receiver.int_to_bitlist(choice_index, receiver.l)
    selected_blinded_exponents = []

    print(f"Receiver: Performing {receiver.l} cryptographic 1-out-of-2 OTs...")
    for j in range(receiver.l):
        # For each OT, we get the two messages (which are blinded exponents)
        # We need to convert them to bytes to be sent through the channel
        m0_int, m1_int = blinded_pairs[j]
        m0_bytes = m0_int.to_bytes(256, 'big') # Use a fixed large size
        m1_bytes = m1_int.to_bytes(256, 'big')

        # Perform the multi-step 1-out-of-2 OT protocol
        ot_sender = DDHOTSender(sender.group)
        ot_receiver = DDHOTReceiver(receiver.group, choice_bits[j])

        A = ot_sender.prepare()
        B = ot_receiver.generate_B(A)
        c0, c1 = ot_sender.respond(B, m0_bytes, m1_bytes)
        recovered_bytes = ot_receiver.recover((c0, c1))
        
        recovered_int = int.from_bytes(recovered_bytes, 'big')
        selected_blinded_exponents.append(recovered_int)
    
    # 3. Receiver uses the obtained values to reconstruct and verify the key
    print("Receiver: Reconstructing final key...")
    is_verified = receiver.reconstruct_and_verify_key(
        choice_index,
        selected_blinded_exponents,
        final_blinding_factor,
        original_messages[choice_index]
    )
    
    return is_verified


if __name__ == "__main__":
    # --- 1. SETUP PHASE ---
    print("--- Adaptive OT Protocol Setup ---")
    
    # Initialize the cryptographic group
    group = DDHGroup()
    
    # Generate a list of dummy messages
    N = 8 # Must be a power of 2
    messages = [f"This is adaptive message #{i}".encode('utf-8') for i in range(N)]
    # Pad messages to the same length
    max_len = max(len(m) for m in messages)
    messages = [m.ljust(max_len, b'\x00') for m in messages]

    # Create the Sender and Receiver for the main protocol
    sender = AdaptiveSender(messages, group)
    receiver = AdaptiveReceiver(N, group)

    # --- 2. INITIALIZATION PHASE ---
    # Sender performs the one-time setup and sends commitments
    commitments = sender.initialize_database()
    receiver.receive_commitments(commitments)
    print("--- Setup Complete ---")

    # --- 3. TRANSFER PHASE (ADAPTIVE QUERIES) ---
    # We can now perform multiple transfers in a loop
    while True:
        try:
            choice_str = input(f"\nEnter the index to retrieve (0-{N-1}), or 'q' to quit: ")
            if choice_str.lower() == 'q':
                break
            
            choice = int(choice_str)
            if not (0 <= choice < N):
                print(f"Invalid index. Please choose between 0 and {N-1}.")
                continue

            # Perform a single secure transfer for the user's choice
            success = perform_one_transfer(choice, sender, receiver, messages)

            if success:
                print(f"✅ Transfer successful! Receiver correctly recovered message for index {choice}.")
            else:
                print(f"❌ Transfer failed! Receiver could not verify the message for index {choice}.")

        except (ValueError, IndexError):
            print("Invalid input. Please enter a number or 'q'.")