import numpy as np
from Crypto.Cipher import AES

real_method = ''

def pksc7_pad(x: bytes, block_size: int):
    padding_to = (len(x) + (block_size - 1))
    padding_to -= (padding_to % block_size)
    padding_size = padding_to - len(x)
    return x.ljust(padding_to, bytes([padding_size]))

def oracle_padding(m: bytes):
    left_size, right_size = np.random.randint(5, 11, 2)
    left_pad = np.random.randint(0, 0x100, left_size, dtype=np.uint8).tobytes()
    right_pad = np.random.randint(0, 0x100, right_size, dtype=np.uint8).tobytes()
    return pksc7_pad(left_pad + m + right_pad, 16)

def encryption_oracle(m):
    global real_method
    m = oracle_padding(m)
    key = np.random.randint(0, 0x100, 16, dtype=np.uint8).tobytes()

    if np.random.choice([0, 1]) == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        real_method = 'ECB'
    else:
        IV = np.random.randint(0, 0x100, 16, dtype=np.uint8).tobytes()
        cipher = AES.new(key, AES.MODE_CBC, IV)
        real_method = 'CBC'
    
    return cipher.encrypt(m)
    
for round in range(10):
    m = b'YELLOW SUBMARINE' * 10
    c = encryption_oracle(m)

    blocks = []
    for i in range(0, len(c), 16):
        blocks.append(c[i : i + 16])

    detect_result = ''

    if len(set(blocks)) < len(blocks):
        detect_result = 'ECB'
    else:
        detect_result = 'CBC'
    
    if detect_result == real_method:
        print(f'({round + 1}/10) [+] Success, res: {detect_result}')
    else:
        print(f'({round + 1}/10) [-] Fail, res: {detect_result}')