import hashlib
import base64
from Crypto.Cipher import AES
import numpy as np

"""
passport: 12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4
"""

""" GET UNKNOW NUMBER """

unknow_num = sum([int(i) * int(j) for i, j in zip('111116', '731731')]) % 10
print(f'unknow_num: {unknow_num}')

""" GET K_SEED """

mrz = b'12345678<8' + b'1110182' + b'111116' + str(unknow_num).encode()
k_seed = hashlib.sha1(mrz).hexdigest()[:32]
print(f'k_seed: {k_seed}')

""" GET K_A AND K_B"""

k_seed = bytes.fromhex(k_seed)
d_h = hashlib.sha1(k_seed + b'\x00\x00\x00\x01').hexdigest()[:32]
k_a = bytes.fromhex(d_h[:16])
k_b = bytes.fromhex(d_h[16:32])

def check(k: bytes):
    new_k = b''
    for i in k:
        i &= ~0x1
        cnt = 0
        for j in range(1, 8):
            cnt += 1 if i & (1 << j) != 0 else 0
        if cnt % 2 == 0:
            i |= 0x1
        new_k += bytes([i])
    return new_k

k_a = check(k_a)
k_b = check(k_b)
key = k_a + k_b
print(f'key: ' + ''.join(['%02x' % i for i in key]))

""" DECRYPT """

c = b'9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
c = base64.b64decode(c)

IV = b'\x00' * 16
cipher = AES.new(key, AES.MODE_CBC, IV)

m = cipher.decrypt(c).replace(b'\x00', b'').replace(b'\01', b'')
print(m.decode())