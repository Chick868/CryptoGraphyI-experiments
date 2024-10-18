import base64
import numpy as np
from Crypto.Cipher import AES

BLK_SIZE = 16

unknown_string = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
KEY = np.random.randint(0, 0x100, BLK_SIZE, dtype=np.uint8).tobytes()
RANDOM_PREFIX_LENGTH = np.random.randint(1, 0x40)
RANDOM_PREFIX = np.random.randint(0, 0x100, RANDOM_PREFIX_LENGTH, dtype=np.uint8).tobytes()

def upper_align(x: int, align: int):
    target = x + align - 1
    target = target - (target % align)
    return target

def pksc7_pad(x: bytes, block_size: int):
    padding_to = (len(x) + (block_size - 1))
    padding_to -= (padding_to % block_size)
    padding_size = padding_to - len(x)
    return x.ljust(padding_to, bytes([padding_size]))

def encryption_oracle(m):
    m = RANDOM_PREFIX + m + unknown_string
    m = pksc7_pad(m, BLK_SIZE)

    cipher = AES.new(KEY, AES.MODE_ECB)

    return cipher.encrypt(m)

def single_byte_crack(m, size, prefix_len):
    prepend = b'A' * ((BLK_SIZE - prefix_len) % BLK_SIZE)
    prepend += b'A' * ((BLK_SIZE - 1) - (len(m) % BLK_SIZE))
    for ch in range(0, 0x100):
        payload = prepend + m + bytes([ch])
        if encryption_oracle(payload)[:size] == encryption_oracle(prepend)[:size]:
            return ch
    return None

def creak_prefix_len():
    # get which block that prefix ends
    c1 = encryption_oracle(b'A')
    c2 = encryption_oracle(b'B')
    iblock = 0

    for i in range(0, len(c1), BLK_SIZE):
        if c1[i : i + BLK_SIZE] != c2[i : i + BLK_SIZE]:
            iblock = i // BLK_SIZE

    length = iblock * BLK_SIZE

    # get accurate pos in block
    prepend = b''
    while True:
        if encryption_oracle(prepend + b'A')[ : (iblock + 1) * BLK_SIZE] == \
                encryption_oracle(prepend + b'B')[ : (iblock + 1) * BLK_SIZE]:
            length += BLK_SIZE - len(prepend)
            break
        prepend += b'A'
    return length
    

def crack():
    prefix_len = creak_prefix_len()

    m = b''
    size = BLK_SIZE + upper_align(prefix_len, BLK_SIZE)

    while True:
        ch = single_byte_crack(m, size, prefix_len)
        if ch:
            m += bytes([ch])
        else:
            return m
        if len(m) % BLK_SIZE == 0:
            size += BLK_SIZE

m = crack()
print(f'unknown string: \n{m.decode()}')
