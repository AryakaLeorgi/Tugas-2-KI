import socket
from des_functions import string_to_bits, bits_to_string, des_process, generate_subkeys

# Key dan subkeys
key = "12345678"
key_bits = string_to_bits(key)
subkeys = generate_subkeys(key_bits)

HOST = '127.0.0.1'  # localhost
PORT = 5000

# Buat server socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print("B menunggu koneksi...")
    conn, addr = s.accept()
    with conn:
        print("B terhubung dengan", addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            # terima, dekripsi
            encrypted_bits = [int(b) for b in data.decode()]
            decrypted_bits = des_process(encrypted_bits, subkeys, decrypt=True)
            message = bits_to_string(decrypted_bits)
            print("B terima (decrypted):", message)

            # balas
            reply = "OK123456"
            reply_bits = string_to_bits(reply)
            encrypted_reply = des_process(reply_bits, subkeys, decrypt=False)
            conn.sendall(''.join(str(b) for b in encrypted_reply).encode())
            print("B kirim (encrypted):", reply)
