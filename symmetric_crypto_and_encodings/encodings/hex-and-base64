import base64

hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
raw_bytes = bytes.fromhex(hex_string)
base64_string = base64.b64encode(raw_bytes).decode()

print(base64_string)

import base64

base64_string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
hex_string = base64.b64decode(base64_string).hex()

print(hex_string)
