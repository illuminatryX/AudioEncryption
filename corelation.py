# import numpy as np
# import librosa

# def calculate_correlation_coefficient(file1, file2):
#     # Load audio files
#     y1, sr1 = librosa.load(file1, sr=None)
#     y2, sr2 = librosa.load(file2, sr=None)
    
#     # Ensure both audio files have the same sample rate
#     if sr1 != sr2:
#         raise ValueError("Sample rates of the audio files do not match.")

#     # Trim the audio files to have the same length (optional)
#     min_length = min(len(y1), len(y2))
#     y1 = y1[:min_length]
#     y2 = y2[:min_length]
    
#     # Calculate correlation coefficient
#     correlation = np.corrcoef(y1, y2)[0, 1]

#     return correlation

# # Example usage
# file2 = "decrypted_2.wav"
# file1 = "encrypted_2.wav"

# corr_coeff = calculate_correlation_coefficient(file1, file2)
# print("Correlation Coefficient:", corr_coeff)

import numpy as np
import librosa

def analyze_noise(file_path, duration=None):
    # Load audio file
    audio, sr = librosa.load(file_path, sr=None, duration=duration)

    # Calculate noise statistics
    mean_noise = np.mean(audio)
    

    return mean_noise

# Example usage
file_path = "2_decrypted.wav"
mean_noise = analyze_noise(file_path)

print("Mean Noise: for "+file_path+" "+ str(mean_noise))


    
