import struct

# === Constants and Serpent S-Boxes ===
FRAC = 0x9e3779b9
S = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 14, 8, 2, 4, 9, 1, 7, 5, 11, 3, 6, 0, 10, 12, 13],
    [8, 14, 7, 11, 1, 3, 4, 5, 13, 12, 6, 9, 0, 2, 10, 15],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [15, 13, 10, 6, 5, 8, 3, 11, 0, 14, 9, 7, 4, 12, 2, 1],
    [1, 10, 4, 2, 8, 0, 14, 7, 11, 6, 5, 12, 13, 9, 3, 15],
    [10, 15, 4, 2, 3, 6, 7, 0, 8, 12, 1, 9, 14, 11, 13, 5],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
]

# === Serpent Key Schedule ===
def ROTL(A, n):
    return ((A << n) | (A >> (32 - n))) & 0xFFFFFFFF

def get_pre(k):
    x = [0] * (140 + 8)
    for i in range(4):  # Only 128-bit key: 4 words
        x[i] = k[i]
    for i in range(4, 140):
        x[i] = ROTL(x[i-8] ^ x[i-5] ^ x[i-3] ^ x[i-1] ^ FRAC ^ (i - 8), 11)
    return x[8:140]

def get_sk(w):
    sk = [[0 for _ in range(4)] for _ in range(33)]
    for i in range(33):
        p = 32 + 3 - i
        for k in range(32):
            idx = ((w[4*i+0] >> k) & 1) << 0 | ((w[4*i+1] >> k) & 1) << 1 | ((w[4*i+2] >> k) & 1) << 2 | ((w[4*i+3] >> k) & 1) << 3
            s = S[p % 8][idx]
            for j in range(4):
                sk[i][j] |= ((s >> j) & 1) << k
    return sk

def key_schedule_128bit(user_key_bytes):
    if len(user_key_bytes) != 16:
        raise ValueError("Key must be exactly 128 bits (16 bytes).")
    key_words = list(struct.unpack('>4I', user_key_bytes)) + [0]*4  # Add 0s for rest
    w = get_pre(key_words)
    return get_sk(w)

# === Test for 128-bit Repeatability ===
def test_serpent_128bit_key_repeatability():
    test_key = "16byte_test_key!"  # Exactly 16 characters
    key_bytes = test_key.encode()

    subkeys1 = key_schedule_128bit(key_bytes)
    subkeys2 = key_schedule_128bit(key_bytes)

    key1a = struct.pack('>4I', *subkeys1[0])
    key2a = struct.pack('>4I', *subkeys1[1])
    key3a = struct.pack('>4I', *subkeys1[2])

    key1b = struct.pack('>4I', *subkeys2[0])
    key2b = struct.pack('>4I', *subkeys2[1])
    key3b = struct.pack('>4I', *subkeys2[2])

    print("\n--- Serpent 128-bit Key Schedule Check ---")
    print("Key1 Match:", key1a == key1b)
    print("Key2 Match:", key2a == key2b)
    print("Key3 Match:", key3a == key3b)
    print("------------------------------------------")

    print("\nDerived Keys (Hex):")
    print("Key1:", key1a.hex())
    print("Key2:", key2a.hex())
    print("Key3:", key3a.hex())
    print("------------------------------------------")

if __name__ == "__main__":
    test_serpent_128bit_key_repeatability()
