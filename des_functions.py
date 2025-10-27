
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFT = [1, 1, 2, 2, 2, 2, 2, 2,
         1, 2, 2, 2, 2, 2, 2, 1]

S_BOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
]

# --- Core functions ---
def string_to_bits(s):
    return [int(b) for c in s for b in format(ord(c), '08b')]

def bits_to_string(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        chars.append(chr(int(''.join(str(b) for b in byte), 2)))
    return ''.join(chars)

def permute(block, table):
    return [block[i - 1] for i in table]

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def shift_left(block, n):
    return block[n:] + block[:n]

def generate_subkeys(key_bits):
    key = permute(key_bits, PC1)
    C, D = key[:28], key[28:]
    subkeys = []
    for shift in SHIFT:
        C = shift_left(C, shift)
        D = shift_left(D, shift)
        CD = C + D
        subkeys.append(permute(CD, PC2))
    return subkeys

def s_box_substitution(bits):
    output = []
    for i in range(8):
        block = bits[i * 6:(i + 1) * 6]
        row = int(f"{block[0]}{block[-1]}", 2)
        col = int(''.join(map(str, block[1:5])), 2)
        s_val = S_BOX[i % len(S_BOX)][row][col]  # Reuse S-box 1–2 pattern
        output += [int(b) for b in format(s_val, '04b')]
    return output

def des_process(block, subkeys, decrypt=False):
    block = permute(block, IP)
    L, R = block[:32], block[32:]
    keys = reversed(subkeys) if decrypt else subkeys
    for key in keys:
        expanded_R = permute(R, E)
        xored = xor(expanded_R, key)
        substituted = s_box_substitution(xored)
        permuted = permute(substituted, P)
        new_R = xor(L, permuted)
        L, R = R, new_R
    combined = R + L
    return permute(combined, FP)

def main():
    plaintext = "ABCDEFGH"  
    key = "12345678"         

    plaintext_bits = string_to_bits(plaintext)
    key_bits = string_to_bits(key)
    subkeys = generate_subkeys(key_bits)

    encrypted_bits = des_process(plaintext_bits, subkeys, decrypt=False)
    decrypted_bits = des_process(encrypted_bits, subkeys, decrypt=True)

    encrypted = bits_to_string(encrypted_bits)
    decrypted = bits_to_string(decrypted_bits)

    print("Plaintext :", plaintext)
    print("Key       :", key)
    print("Encrypted :", encrypted)
    print("Decrypted :", decrypted)

if __name__ == "__main__":
    main()
