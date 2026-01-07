import numpy as np

char_freq = {
    'a': 0.06517, 'b': 0.01242, 'c': 0.02173, 'd': 0.03483,
    'e': 0.10414, 'f': 0.01974, 'g': 0.01587, 'h': 0.04928,
    'i': 0.05568, 'j': 0.00097, 'k': 0.00561, 'l': 0.03318,
    'm': 0.02027, 'n': 0.05668, 'o': 0.05963, 'p': 0.01316,
    'q': 0.00084, 'r': 0.04988, 's': 0.05188, 't': 0.07232,
    'u': 0.02276, 'v': 0.00824, 'w': 0.01703, 'x': 0.00141,
    'y': 0.01428, 'z': 0.00051, ' ': 0.19181
}

freq_array = np.zeros(256)
for char, freq in char_freq.items():
    freq_array[ord(char)] = freq
    freq_array[ord(char.upper())] = freq

hex_data = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
data = np.frombuffer(bytes.fromhex(hex_data), dtype=np.uint8)
best_score = -1
best_key = None
best_plaintext = None

for key in range(256):
    decrypted = np.bitwise_xor(data, key)
    try:
        score = freq_array[decrypted].sum()
        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = bytes(decrypted).decode()
    except UnicodeDecodeError:
        continue

print(f'Best key: {best_key} (Char: {chr(best_key)})')
print('Decrypted message:', best_plaintext)
