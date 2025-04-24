import wave
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import struct

# === Constants ===
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
    for i in range(8):
        x[i] = k[i]
    for i in range(8, 140):
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

def key_schedule(user_key_bytes):
    # Only for 128-bit key 
    key_words = list(struct.unpack('>4I', user_key_bytes)) + [0, 0, 0, 0]
    w = get_pre(key_words)
    return get_sk(w)

# === Cellular Automaton ===
class CellularAutomaton:
    def __init__(self, rule, key):
        self.rule = rule
        self.state = key

    def evolve(self):
        next_state = ''
        for i in range(len(self.state)):
            left = self.state[i - 1]
            center = self.state[i]
            right = self.state[(i + 1) % len(self.state)]
            next_state += self.rule(left, center, right)
        self.state = next_state

def rule30(left, center, right):
    rule = {
        ('1', '1', '1'): '0',
        ('1', '1', '0'): '0',
        ('1', '0', '1'): '0',
        ('1', '0', '0'): '1',
        ('0', '1', '1'): '1',
        ('0', '1', '0'): '1',
        ('0', '0', '1'): '1',
        ('0', '0', '0'): '0'
    }
    return rule[(left, center, right)]

def convert_key_to_binary_bytes(key_bytes):
    return ''.join(format(b, '08b') for b in key_bytes)

# === Encryption ===
def encrypt_audio(input_file, output_file, key):
    with wave.open(input_file, 'rb') as f:
        params = f.getparams()
        audio_frames = f.readframes(params.nframes)

    key_bytes = key.encode()
    if len(key_bytes) != 16:
        raise ValueError("Key must be exactly 16 characters (128 bits) for AES-128.")
    subkeys = key_schedule(key_bytes)

    key1 = struct.pack('>4I', *subkeys[0])  # AES key
    key2 = struct.pack('>4I', *subkeys[1])  # IV
    key3 = struct.pack('>4I', *subkeys[2])  # Cellular Automaton

    key_binary = convert_key_to_binary_bytes(key3)
    automaton = CellularAutomaton(rule30, key_binary)
    automaton.evolve()
    keystream = automaton.state

    iv = key2
    cipher = AES.new(key1, AES.MODE_CBC, iv)
    padded_frames = pad(audio_frames, AES.block_size)
    encrypted_frames = cipher.encrypt(padded_frames)

    final_encrypted = bytearray()
    for i in range(len(encrypted_frames)):
        final_encrypted.append(encrypted_frames[i] ^ int(keystream[i % len(keystream)]))

    with wave.open(output_file, 'wb') as f:
        f.setparams(params)
        f.writeframes(iv + final_encrypted)

# === Decryption ===
def decrypt_audio(input_file, output_file, key):
    with wave.open(input_file, 'rb') as f:
        params = f.getparams()
        encrypted_audio_data = f.readframes(params.nframes)

    iv = encrypted_audio_data[:16]
    encrypted_audio_data = encrypted_audio_data[16:]

    key_bytes = key.encode()
    if len(key_bytes) != 16:
        raise ValueError("Key must be exactly 16 characters (128 bits) for AES-128.")
    subkeys = key_schedule(key_bytes)

    key1 = struct.pack('>4I', *subkeys[0])  # AES key
    key3 = struct.pack('>4I', *subkeys[2])  # Cellular Automaton

    key_binary = convert_key_to_binary_bytes(key3)
    automaton = CellularAutomaton(rule30, key_binary)
    automaton.evolve()
    keystream = automaton.state

    xored_back = bytearray()
    for i in range(len(encrypted_audio_data)):
        xored_back.append(encrypted_audio_data[i] ^ int(keystream[i % len(keystream)]))

    cipher = AES.new(key1, AES.MODE_CBC, iv)
    decrypted_frames = unpad(cipher.decrypt(bytes(xored_back)), AES.block_size)

    with wave.open(output_file, 'wb') as f:
        f.setparams(params)
        f.writeframes(decrypted_frames)

# === Execution ===
if __name__ == "__main__":
    key = input("Enter the key: ")
    input_file = 'file_example_WAV_10MG.wav'
    encrypted_file = 'adv_encrypted_audio.wav'
    decrypted_file = 'adv_decrypted_audio.wav'

    encrypt_audio(input_file, encrypted_file, key)
    decrypt_audio(encrypted_file, decrypted_file, key)
    print("Encryption and Decryption complete using AES-128.")
