import wave
import os
import struct
import numpy as np
import librosa
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

# === Audio Processing Functions ===
def encrypt_audio(input_file, output_file, key):
    with wave.open(input_file, 'rb') as f:
        params = f.getparams()
        audio_frames = f.readframes(params.nframes)

    key_bytes = key.encode()
    if len(key_bytes) != 16:
        raise ValueError("Key must be exactly 16 characters (128 bits) for AES-128.")
    subkeys = key_schedule(key_bytes)

    key1 = struct.pack('>4I', *subkeys[0])
    key2 = struct.pack('>4I', *subkeys[1])
    key3 = struct.pack('>4I', *subkeys[2])

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
        f.writeframes(final_encrypted)

def decrypt_audio(input_file, output_file, key):
    with wave.open(input_file, 'rb') as f:
        params = f.getparams()
        encrypted_audio_data = f.readframes(params.nframes)

    key_bytes = key.encode()
    if len(key_bytes) != 16:
        raise ValueError("Key must be exactly 16 characters (128 bits) for AES-128.")
    subkeys = key_schedule(key_bytes)

    key1 = struct.pack('>4I', *subkeys[0])
    key2 = struct.pack('>4I', *subkeys[1])
    key3 = struct.pack('>4I', *subkeys[2])
    iv = key2

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

# === Analysis Functions ===
def calculate_correlation_coefficient(file1, file2):
    y1, sr1 = librosa.load(file1, sr=None)
    y2, sr2 = librosa.load(file2, sr=None)
    
    if sr1 != sr2:
        raise ValueError("Sample rates of the audio files do not match.")

    min_length = min(len(y1), len(y2))
    y1 = y1[:min_length]
    y2 = y2[:min_length]
    
    correlation = np.corrcoef(y1, y2)[0, 1]
    return correlation

def analyze_noise(file_path, duration=None):
    audio, sr = librosa.load(file_path, sr=None, duration=duration)
    mean_noise = np.mean(audio)
    return str(mean_noise)

def calculate_snr(original, processed):
    # Calculate Signal-to-Noise Ratio
    signal_power = np.mean(original ** 2)
    noise_power = np.mean((original - processed) ** 2)
    if noise_power == 0:
        return float('inf')
    snr = 10 * np.log10(signal_power / noise_power)
    return snr

def calculate_rmse(original, processed):
    # Calculate Root Mean Square Error
    return np.sqrt(np.mean((original - processed) ** 2))

def plot_audio_waveform(file_path, output_path):
    audio, sr = librosa.load(file_path, sr=None)
    plt.figure(figsize=(12, 4))
    plt.plot(audio)
    plt.xlabel('Time (s)')
    plt.ylabel('Amplitude')
    plt.savefig(output_path)
    plt.close()

def process_audio_files():
    # Create necessary directories
    os.makedirs('Results/encrypted', exist_ok=True)
    os.makedirs('Results/decrypted', exist_ok=True)
    os.makedirs('Results/Results', exist_ok=True)

    # Get list of audio files
    audio_files = [f for f in os.listdir('Results/samples') if f.endswith('.wav')]
    
    # Process each audio file
    results = []
    for audio_file in audio_files:
        base_name = os.path.splitext(audio_file)[0]
        input_path = os.path.join('Results/samples', audio_file)
        encrypted_path = os.path.join('Results/encrypted', f'{base_name}_encrypted.wav')
        decrypted_path = os.path.join('Results/decrypted', f'{base_name}_decrypted.wav')
        
        # Encryption and decryption
        key = "YourSecretKey123"  # You might want to change this
        encrypt_audio(input_path, encrypted_path, key)
        decrypt_audio(encrypted_path, decrypted_path, key)
        
        # Generate plots
        plot_audio_waveform(encrypted_path, os.path.join('Results/Results', f'{base_name}_encrypted.png'))
        plot_audio_waveform(decrypted_path, os.path.join('Results/Results', f'{base_name}_decrypted.png'))
        
        # Load audio data for analysis
        original_audio, _ = librosa.load(input_path, sr=None)
        encrypted_audio, _ = librosa.load(encrypted_path, sr=None)
        decrypted_audio, _ = librosa.load(decrypted_path, sr=None)
        
        # Ensure all arrays have the same length
        min_length = min(len(original_audio), len(encrypted_audio), len(decrypted_audio))
        original_audio = original_audio[:min_length]
        encrypted_audio = encrypted_audio[:min_length]
        decrypted_audio = decrypted_audio[:min_length]
        
        # Calculate metrics
        original_encrypted_corr = calculate_correlation_coefficient(input_path, encrypted_path)
        original_decrypted_corr = calculate_correlation_coefficient(input_path, decrypted_path)
        
        original_noise = analyze_noise(input_path)
        encrypted_noise = analyze_noise(encrypted_path)
        decrypted_noise = analyze_noise(decrypted_path)
        
        encrypted_snr = calculate_snr(original_audio, encrypted_audio)
        decrypted_snr = calculate_snr(original_audio, decrypted_audio)
        
        encrypted_rmse = calculate_rmse(original_audio, encrypted_audio)
        decrypted_rmse = calculate_rmse(original_audio, decrypted_audio)
        
        results.append({
            'audio_name': base_name,
            'encrypted_correlation': original_encrypted_corr,
            'decrypted_correlation': original_decrypted_corr,
            'original_noise': original_noise,
            'encrypted_noise': encrypted_noise,
            'decrypted_noise': decrypted_noise,
            'encrypted_snr': encrypted_snr,
            'decrypted_snr': decrypted_snr,
            'encrypted_rmse': encrypted_rmse,
            'decrypted_rmse': decrypted_rmse
        })
    
    # Write results to file
    with open('Results/analysis.txt', 'w') as f:
        f.write("Audio Analysis Results\n")
        f.write("=====================\n\n")
        for result in results:
            f.write(f"Audio: {result['audio_name']}\n")
            f.write(f"Original vs Encrypted Correlation: {result['encrypted_correlation']:.4f}\n")
            f.write(f"Original vs Decrypted Correlation: {result['decrypted_correlation']:.4f}\n")
            f.write(f"Original Noise Level: {result['original_noise']}\n")
            f.write(f"Encrypted Noise Level: {result['encrypted_noise']}\n")
            f.write(f"Decrypted Noise Level: {result['decrypted_noise']}\n")
            f.write(f"Encrypted SNR (dB): {result['encrypted_snr']:.2f}\n")
            f.write(f"Decrypted SNR (dB): {result['decrypted_snr']:.2f}\n")
            f.write(f"Encrypted RMSE: {result['encrypted_rmse']:.4f}\n")
            f.write(f"Decrypted RMSE: {result['decrypted_rmse']:.4f}\n")
            f.write("-" * 50 + "\n")

if __name__ == "__main__":
    process_audio_files()
    print("Processing complete. Check the Results directory for outputs.") 