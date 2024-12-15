import random
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def hex_to_bin(s):
    mp = {
        '0': "0000", '1': "0001", '2': "0010", '3': "0011",
        '4': "0100", '5': "0101", '6': "0110", '7': "0111",
        '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
        'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"
    }
    s = s.upper()  
    return ''.join(mp[ch] for ch in s)


def bin_to_hex(s):
    mp = {
        "0000": '0', "0001": '1', "0010": '2', "0011": '3', "0100": '4',
        "0101": '5', "0110": '6', "0111": '7', "1000": '8', "1001": '9',
        "1010": 'A', "1011": 'B', "1100": 'C', "1101": 'D', "1110": 'E',
        "1111": 'F'
    }
    return ''.join(mp[s[i:i + 4]] for i in range(0, len(s), 4))

def pad_message(msg):
    """Pad message to be a multiple of 8 bytes."""
    padding_len = 8 - (len(msg) % 8)
    return msg + chr(padding_len) * padding_len


def unpad_message(msg):
    """Remove padding from message."""
    padding_len = ord(msg[-1])
    return msg[:-padding_len]

def bin_to_dec(binary):
    return int(binary, 2)

def dec_to_bin(num):
    return bin(num).replace("0b", "").zfill(64)

def permute(k, arr):
    """Perform permutation on a string based on the given array."""
    return ''.join(k[i - 1] for i in arr)


def shift_left(k, nth_shifts):
    return k[nth_shifts:] + k[:nth_shifts]

def xor(a, b):
    return ''.join('1' if a[i] != b[i] else '0' for i in range(len(a)))

def generate_key():
    return ''.join(random.choice('01') for _ in range(64))

def generate_hex_key():
    random_key = generate_key()  
    hex_key = hex(int(random_key, 2))[2:].zfill(16).upper()  
    return hex_key


def generate_rsa_keys():
    """Generate RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(public_key, message):
    """Encrypt message using RSA public key."""
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return cipher.encrypt(message)

def decrypt_rsa(private_key, ciphertext):
    """Decrypt ciphertext using RSA private key."""
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    return cipher.decrypt(ciphertext)

s_box = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
 
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
 
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
 
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
 
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
 
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
 
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
 
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
        ]

initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]
 
exp_box = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]
 
perm = [16,  7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2,  8, 24, 14,
       32, 27,  3,  9,
       19, 13, 30,  6,
       22, 11,  4, 25]
 


final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

def generate_key():
    return ''.join(random.choice('01') for _ in range(64))

def key_schedule(key):
    """Generate round keys for DES."""
    key = permute(key, [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ])

    round_keys_bin = []
    left, right = key[:28], key[28:]
    shifts = [1, 1, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 1, 2]

    for shift in shifts:
        left = shift_left(left, shift)
        right = shift_left(right, shift)
        combined = left + right
        round_key = permute(combined, [
            14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
        ])
        print(f"Generated round key: {round_key}, Length: {len(round_key)} bits")
        round_keys_bin.append(round_key)

    return round_keys_bin




def f_function(R, K):
    """F-function for DES."""
    try:
        exp_box = [
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20,
            21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ]
        expanded_R = permute(R, exp_box)
        if len(expanded_R) != 48:
            raise ValueError(f"Expanded R length is invalid: {len(expanded_R)} (expected 48)")

        xor_result = xor(expanded_R, K)
        if len(xor_result) != 48:
            raise ValueError(f"XOR result length is invalid: {len(xor_result)} (expected 48)")

        sbox_results = []  
        for i in range(8):
            block = xor_result[i * 6:(i + 1) * 6]
            if len(block) != 6:
                raise ValueError(f"S-Box block length is invalid: {len(block)} (expected 6 bits)")

            row_bits = block[0] + block[5]
            row = int(row_bits, 2)  
            col_bits = block[1:5]
            col = int(col_bits, 2)  

            print(f"S-Box {i + 1}: Block: {block}, Row bits: {row_bits}, Column bits: {col_bits}, Row: {row}, Column: {col}")

            if not (0 <= row < 4):
                raise ValueError(f"S-Box row index out of range: {row} (expected 0-3)")
            if not (0 <= col < 16):
                raise ValueError(f"S-Box column index out of range: {col} (expected 0-15)")

            sbox_value = s_box[i][row][col]
            sbox_value_bin = bin(sbox_value)[2:].zfill(4)

            print(f"S-Box {i + 1}: Retrieved value: {sbox_value}, Binary: {sbox_value_bin}")

            sbox_results.append(sbox_value_bin)

        sbox_output = ''.join(sbox_results)

        perm = [
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18,
            31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6,
            22, 11, 4, 25
        ]
        return permute(sbox_output, perm)

    except Exception as e:
        print(f"Error in F-function: {e}")
        raise



def encrypt_block(plain_text, keys):
    if len(plain_text) != 64:
        raise ValueError(f"Input block length is invalid: {len(plain_text)} (expected 64 bits)")

    print(f"Encrypting block with input length: {len(plain_text)} bits")
    text = permute(plain_text, initial_perm)
    left, right = text[:32], text[32:]

    for i in range(16):
        temp = right
        right = xor(left, f_function(right, keys[i]))
        left = temp
        print(f"After round {i + 1}: Left: {left}, Right: {right}")

    combined = right + left  
    return permute(combined, final_perm)




def decrypt_block(cipher_text, keys):
    text = permute(cipher_text, initial_perm)
    left, right = text[:32], text[32:]

    for i in range(15, -1, -1):
        left, right = right, xor(left, f_function(right, keys[i]))

    combined = right + left  
    return permute(combined, final_perm)

def start_server(port, private_key):
    """Start the server to receive encrypted DES key and message."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', port))
    server_socket.listen(1)
    print(f"Server listening on port {port}...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr} established.")

    encrypted_des_key = conn.recv(256)  
    des_key = decrypt_rsa(private_key, encrypted_des_key)
    print(f"Decrypted DES Key: {des_key.hex()}")

    
    des_keys = key_schedule(hex_to_bin(des_key.hex()))

   
    encrypted_message = conn.recv(1024)
    print(f"Encrypted message received (hex): {encrypted_message.hex()}")

   
    decrypted_message = decrypt_block(hex_to_bin(encrypted_message.decode()), des_keys)
    print(f"Decrypted message: {unpad_message(decrypted_message)}")

    conn.close()
    server_socket.close()

def start_client(host, port, des_key, public_key):
    """Start the client to send encrypted DES key and message."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")

    # Encrypt the DES key using RSA public key
    encrypted_des_key = encrypt_rsa(public_key, des_key.encode())
    print(f"Encrypted DES Key: {encrypted_des_key.hex()}")

    # Send the encrypted DES key to the server
    client_socket.send(encrypted_des_key)

    # Send the encrypted message
    message = "Hello, this is a secret message."
    padded_message = pad_message(message)
    encrypted_message = encrypt_block(hex_to_bin(padded_message), des_key)  # Encrypt message using DES
    client_socket.send(bin_to_hex(encrypted_message).encode())
    print(f"Encrypted message sent (hex): {bin_to_hex(encrypted_message)}")

    client_socket.close()


if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()

    with open("server_public.pem", "wb") as f:
        f.write(public_key)

    import threading
    server_thread = threading.Thread(target=start_server, args=(5000, private_key))
    server_thread.start()

    des_key = get_random_bytes(8)  
    with open("server_public.pem", "rb") as f:
        server_public_key = f.read()
    start_client('localhost', 5000, des_key, server_public_key)

    server_thread.join()