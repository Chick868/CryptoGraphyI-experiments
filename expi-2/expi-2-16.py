import numpy as np
from Crypto.Cipher import AES

KEY = np.random.randint(0, 0x100, 16, dtype=np.uint8).tobytes()
IV = np.random.randint(0, 0x100, 16, dtype=np.uint8).tobytes()

PREPEND = b'comment1=cooking%20MCs;userdata='
APPEND = b';comment2=%20like%20a%20pound%20of%20bacon'

BLK_SIZE = 16

def upper_align(x: int, align: int):
    target = x + align - 1
    target = target - (target % align)
    return target

def pksc7_pad(x: bytes, block_size: int):
    padding_to = (len(x) + (block_size - 1))
    padding_to -= (padding_to % block_size)
    padding_size = padding_to - len(x)
    return x.ljust(padding_to, bytes([padding_size]))

def func1(m: bytes):
    # first encrypt the message with prepend and append
    m = m.replace(b';', b'%3B').replace(b'=', b'%3D')
    m = PREPEND + m + APPEND
    m = pksc7_pad(m, BLK_SIZE)

    cipher = AES.new(KEY, AES.MODE_CBC, IV)

    return cipher.encrypt(m)

def func2(c: bytes):
    # decrypt ciphertext and find `;admin=true;`
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    m = cipher.decrypt(c)
    if b';admin=true;' in m:
        return m
    return None

def attack(target: bytes):
    # target must in one single block
    assert len(target) <= BLK_SIZE

    """ align `prepend` to BLK_SIZE """
    prepend_len = len(PREPEND)
    # payload start from here
    start_pos = upper_align(prepend_len, BLK_SIZE)
    # align to BLK_SIZE
    padding_prepend = b'A' * (start_pos - prepend_len)

    """ get ciphertext, we use two blocks """
    input_string = b'A' * BLK_SIZE * 2
    c = func1(padding_prepend + input_string)

    """ C_{n-1} ^= P_{n} ^ target_block """
    # pad payload to BLK_SIZE
    target = pksc7_pad(target, BLK_SIZE)

    # inject attack
    c = bytearray(c)
    c[start_pos:start_pos + BLK_SIZE] = [i ^ j ^ k for i, j, k in zip(
        c[start_pos:start_pos + BLK_SIZE], 
        input_string[BLK_SIZE:BLK_SIZE * 2], 
        target)]
    c = bytes(c)

    return func2(c)

m = attack(b';admin=true;')
if m:
    print('Admin!')
    print(m)
