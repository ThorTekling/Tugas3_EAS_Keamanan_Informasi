import socket
from main import encrypt_block, key_schedule, pad_message, encrypt_rsa, bin_to_hex, hex_to_bin
from Crypto.Random import get_random_bytes

def fetch_public_key(pka_ip, pka_port):
    """Fetch the server's public key from the Public Key Authority."""
    try:
        pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka_socket.connect((pka_ip, pka_port))
        public_key = pka_socket.recv(1024)
        if not public_key:
            raise ValueError("No public key received from PKA.")
        print("Public key fetched from PKA.")
        return public_key
    except Exception as e:
        print(f"Failed to fetch public key from PKA: {e}")
        exit(1)
    finally:
        pka_socket.close()

server_ip = '127.0.0.1'
server_port = 5000
pka_ip = '127.0.0.1'
pka_port = 6000

try:
    # Fetch public key from PKA
    server_public_key = fetch_public_key(pka_ip, pka_port)

    # Generate DES key and its schedule
    des_key = get_random_bytes(8)  # 8 bytes = 64 bits
    des_keys = key_schedule(hex_to_bin(des_key.hex()))  # Generate DES key schedule
    print(f"Generated DES Key (hex): {des_key.hex()}")

    # Encrypt DES key with RSA
    encrypted_des_key = encrypt_rsa(server_public_key, des_key)
    print(f"Encrypted DES Key (hex): {encrypted_des_key.hex()}")

    # Prepare the plaintext and pad it
    plaintext = "Test message!"
    padded_plaintext = pad_message(plaintext).encode('utf-8')  # Pad message
    binary_plaintext = ''.join(format(byte, '08b') for byte in padded_plaintext)  # Convert to binary string

    print(f"Padded binary plaintext: {binary_plaintext}, Length: {len(binary_plaintext)} bits")

    # Ensure the binary plaintext is a multiple of 64 bits
    if len(binary_plaintext) % 64 != 0:
        raise ValueError("Binary plaintext length is not a multiple of 64 bits.")

    encrypted_message = ''
    for i in range(0, len(binary_plaintext), 64):
        block = binary_plaintext[i:i + 64]  # Process 64-bit blocks
        print(f"Encrypting block: {block}, Length: {len(block)} bits")
        encrypted_message += encrypt_block(block, des_keys)

    encrypted_message_hex = bin_to_hex(encrypted_message)  # Convert to hexadecimal
    print(f"Encrypted message (hex): {encrypted_message_hex}")

    # Send the encrypted DES key and message to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Waiting for connection...")

    # Wrap the connection attempt in a try-except block
    try:
        client_socket.connect((server_ip, server_port))  # Ensure to use the correct IP and port
        print("Connected to server")
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        exit(1)

    client_socket.send(encrypted_des_key)
    print("Encrypted DES key sent to server.")
    
    client_socket.send(encrypted_message_hex.encode())
    print("Encrypted message sent to server.")

except ValueError as e:
    print(f"ValueError: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

finally:
    # Ensure client socket is closed
    if 'client_socket' in locals() and client_socket:
        client_socket.close()
        print("Client socket closed.")
