# run_adaptive_ot.py
from src.crypto.ddh_group import DDHGroup
from src.roles.adaptive_sender import AdaptiveSender
from src.roles.adaptive_receiver import AdaptiveReceiver
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
    
    blinded_pairs, final_blinding_factor = sender.prepare_transfer_values()

    choice_bits = receiver.int_to_bitlist(choice_index, receiver.l)
    selected_blinded_exponents = []

    print(f"Receiver: Performing {receiver.l} cryptographic 1-out-of-2 OTs...")
    for j in range(receiver.l):
        m0_int, m1_int = blinded_pairs[j]

        # Add debugging output
        print(f"  OT {j}: choice_bit = {choice_bits[j]}")
        # print(f"  OT {j}: m0_int = {m0_int}")
        # print(f"  OT {j}: m1_int = {m1_int}")

        # Convert the large integer exponents to a fixed-size byte string
        # Need to do mod op to prevent overflow
        key_byte_len = (sender.group.p.bit_length() + 7) // 8
        m0_bytes = (m0_int % sender.group.p).to_bytes(key_byte_len, 'big', signed = False)
        m1_bytes = (m1_int % sender.group.p).to_bytes(key_byte_len, 'big', signed = False)

        ot_sender = DDHOTSender(sender.group)
        ot_receiver = DDHOTReceiver(receiver.group, choice_bits[j])

        try:
            # print(f"  OT {j}: Calling ot_sender.prepare()...")
            A = ot_sender.A
            # print(f"  OT {j}: A = {A}")
            
            # print(f"  OT {j}: Calling ot_receiver.generate_B(A)...")
            B = ot_receiver.generate_B(A)
            # print(f"  OT {j}: B = {B}")
            
            # print(f"  OT {j}: Calling ot_sender.respond(B, m0_bytes, m1_bytes)...")
            c0_bytes, c1_bytes = ot_sender.respond(B, m0_bytes, m1_bytes)
            # print(f"  OT {j}: Got ciphertexts, lengths: {len(c0_bytes)}, {len(c1_bytes)}")
            
            # print(f"  OT {j}: Calling ot_receiver.recover((c0_bytes, c1_bytes))...")
            recovered_bytes = ot_receiver.recover((c0_bytes, c1_bytes))
            
            # Convert the recovered byte string back to an integer
            recovered_int = int.from_bytes(recovered_bytes, 'big')
            selected_blinded_exponents.append(recovered_int)
            print(f"  OT {j}: recovered_int = {recovered_int}")
        except Exception as e:
            print(f"  OT {j}: Failed with error: {e}")
            print(f"  OT {j}: Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            raise e
    
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

        except (ValueError, IndexError):
            print("Invalid input. Please enter a number or 'q'.")
            continue
        
        # Perform the transfer outside the input validation try-catch
        try:
            success = perform_one_transfer(choice, sender, receiver, messages)
            if success:
                print(f"✅ Transfer successful! Receiver correctly recovered message for index {choice}.")
            else:
                print(f"❌ Transfer failed! Receiver could not verify the message for index {choice}.")
        except Exception as e:
            print(f"❌ Transfer failed with error: {e}")
            print(f"Error type: {type(e).__name__}")