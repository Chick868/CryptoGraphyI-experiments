import base64
from Crypto.Cipher import AES

with open('10.txt', 'r') as f:
    c = f.readlines()

def aes_cbc_decrypt(c: bytes, key: bytes, IV: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    assert len(c) % 0x10 == 0 and len(IV) == 0x10
    
    m = []

    block_p = IV
    block_n = None

    for i in range(0, len(c), 0x10):
        block_n = c[i : i + 0x10]
        m += [i ^ j for i, j in zip(cipher.decrypt(block_n), block_p)]
        block_p = block_n

    return bytes(m)

c = base64.b64decode(''.join(c))
key = b'YELLOW SUBMARINE'
IV = b'\x00' * 0x10

print(aes_cbc_decrypt(c, key, IV))