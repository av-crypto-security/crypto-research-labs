def fixed_xor(hex1, hex2):
    b1 = bytes.fromhex(hex1)
    b2 = bytes.fromhex(hex2)
    result = bytes(a ^ b for a, b in zip(b1, b2))
    return result.hex()

s1 = '1c0111001f010100061a024b53535009181c'
s2 = '686974207468652062756c6c277320657965'

print(fixed_xor(s1, s2))
