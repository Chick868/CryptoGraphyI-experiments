import base64
import numpy as np
from Crypto.Cipher import AES

unknown_string = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
KEY = np.random.randint(0, 0x100, 16, dtype=np.uint8).tobytes()

def pksc7_pad(x: bytes, block_size: int):
    padding_to = (len(x) + (block_size - 1))
    padding_to -= (padding_to % block_size)
    padding_size = padding_to - len(x)
    return x.ljust(padding_to, bytes([padding_size]))


def encryption_oracle(m):
    m += unknown_string
    m = pksc7_pad(m, 16)

    cipher = AES.new(KEY, AES.MODE_ECB)

    return cipher.encrypt(m)


def detect_block_size():
    feed = b'A'
    prev_size = 0
    while True:
        c = encryption_oracle(feed)
        if prev_size != 0 and len(c) > prev_size:
            return len(c) - prev_size
        prev_size = len(c)
        feed += b'A'

def detect_mode():
    m = b'YELLOW SUBMARINE' * 10
    c = encryption_oracle(m)
    blocks = []
    for i in range(0, len(c), 16):
        blocks.append(c[i : i + 16])

    if len(set(blocks)) < len(blocks):
        return 'ECB'
    else:
        return None

def single_byte_crack(m, size):
    prepend = b'A' * (15 - (len(m) % 16))
    for ch in range(0, 0x100):
        payload = prepend + m + bytes([ch])
        if encryption_oracle(payload)[:size] == encryption_oracle(prepend)[:size]:
            return ch
    return None


def crack():
    m = b''
    size = 16
    while True:
        ch = single_byte_crack(m, size)
        if ch:
            m += bytes([ch])
        else:
            return m
        if len(m) % 16 == 0:
            size += 16
        

print(f'block size: {detect_block_size()}')
mode = detect_mode()
print(f'mode: ' + mode if mode else 'Not ECB')

m = crack()
print(f'\nunknown string: \n{m.decode()}')
