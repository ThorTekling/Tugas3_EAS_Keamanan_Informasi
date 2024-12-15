import socket

pka_ip = '127.0.0.1'
pka_port = 6000

# Load the public key from file
try:
    with open("server_public.pem", "rb") as pub_file:
        server_public_key = pub_file.read()
    print("Public key loaded successfully.")
except FileNotFoundError:
    print("Error: server_public.pem not found!")
    exit(1)
except Exception as e:
    print(f"Error loading public key: {e}")
    exit(1)

# Set up the server socket to listen for incoming connections
pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    pka_socket.bind((pka_ip, pka_port))
    pka_socket.listen(5)  # Allow up to 5 pending connections
    print(f"PKA Server is running on {pka_ip}:{pka_port}...")
except Exception as e:
    print(f"Error setting up PKA server: {e}")
    exit(1)

try:
    while True:
        print("Waiting for client connection...")
        client_socket, addr = pka_socket.accept()  # Accept client connection
        print(f"Connection from {addr} established.")

        try:
            # Send the server's public key to the client
            client_socket.sendall(server_public_key)
            print(f"Sent public key to {addr}")

        except Exception as e:
            print(f"Error sending public key to {addr}: {e}")
        finally:
            # Close the client socket after sending the public key
            client_socket.close()
            print(f"Connection with {addr} closed.")

except Exception as e:
    print(f"An error occurred in PKA server: {e}")

finally:
    pka_socket.close()
    print("PKA Server shut down.")
