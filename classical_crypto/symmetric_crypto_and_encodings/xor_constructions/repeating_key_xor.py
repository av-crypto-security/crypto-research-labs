# ---------------------------------------------------------- plaintext -> ciphertext -------------------------------------------------
def repeating_key_xor(text: bytes, key: bytes) -> bytes:
    result = bytearray()
    for i in range(len(text)):
        result.append(text[i] ^ key[i % len(key)])
    return result

plaintext = (
    b"Burning 'em, if you ain't quick and nimble\n"
    b"I go crazy when I hear a cymbal"
)

key = b'ICE'
ciphertext = repeating_key_xor(plaintext, key)
print(ciphertext.hex())

# -------------------------------------------------------- ciphertext -> plaintext ---------------------------------------------------
def repeating_key_xor(text: bytes, key: bytes) -> bytes:
    result = bytearray()
    for i in range(len(text)):
        result.append(text[i] ^ key[i % len(key)])
    return result

hex_line = '''0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'''
ciphertext = bytes.fromhex(hex_line)
key = b'ICE'
plaintext = repeating_key_xor(ciphertext, key)

print(plaintext.decode())
