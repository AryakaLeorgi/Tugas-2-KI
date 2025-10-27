import socket
from des_functions import string_to_bits, bits_to_string, des_process, generate_subkeys

# Key dan subkeys
key = "12345678"
key_bits = string_to_bits(key)
subkeys = generate_subkeys(key_bits)

HOST = '127.0.0.1'
PORT = 5000

# Buat client socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    plaintext = "HELLO123"
    bits = string_to_bits(plaintext)
    encrypted = des_process(bits, subkeys, decrypt=False)
    s.sendall(''.join(str(b) for b in encrypted).encode())
    print("A kirim (encrypted):", plaintext)

    data = s.recv(1024)
    encrypted_reply = [int(b) for b in data.decode()]
    decrypted_reply = des_process(encrypted_reply, subkeys, decrypt=True)
    print("A terima (decrypted):", bits_to_string(decrypted_reply))
