from Crypto.Cipher import AES
import numpy as np

next_uid = 0
KEY = np.random.randint(0, 0x100, 16, dtype=np.uint8).tobytes()

def pksc7_pad(x: bytes, block_size: int):
    padding_to = (len(x) + (block_size - 1))
    padding_to -= (padding_to % block_size)
    padding_size = padding_to - len(x)
    return x.ljust(padding_to, bytes([padding_size]))

def strip_tail(m: bytes):
    assert len(m) % 16 == 0
    possible_padding = m[-1]
    if m[-possible_padding:] == bytes([possible_padding]) * possible_padding:
        m = m[:-possible_padding]
    return m

def parse_profile(x: str):
    profile = {}
    pairs = x.split('&')
    for pair in pairs:
        k, v = pair.split('=')
        profile[k] = v
    return profile

def profile_for(email: str):
    global next_uid
    email = email.replace('=', '%3D').replace('&', '%26')
    m = f'email={email}&uid={next_uid}&role=user'.encode()
    m = pksc7_pad(m, 16)
    next_uid += 1

    cipher = AES.new(KEY, AES.MODE_ECB)
    c = cipher.encrypt(m)

    return c

def decrypt_profile(c: bytes):
    cipher = AES.new(KEY, AES.MODE_ECB)
    m = cipher.decrypt(c)
    m = strip_tail(m)
    return parse_profile(m.decode())


#---------- ATTACK ----------#

BLK_SIZE = 16

# first we pad the `user` to a separate block
payload1 = ((BLK_SIZE - len('email=&uid=1&role=')) % BLK_SIZE) * 'A'
# the ciphertext that we will attack
c = profile_for(payload1)

# second we get a block that only contains `admin`
payload2 = ((BLK_SIZE - len('email=')) % BLK_SIZE) * 'A'
payload2 += pksc7_pad(b'admin', BLK_SIZE).decode()
c2 = profile_for(payload2)
admin_block = c2[BLK_SIZE:2 * BLK_SIZE]

# substitute the ciphertext
c = bytearray(c)
c[-BLK_SIZE:] = admin_block
c = bytes(c)

#----------------------------#
print(decrypt_profile(c))