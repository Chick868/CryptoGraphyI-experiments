from Crypto.Util.number import *
import gmpy2


while True:
    try:
        p = getPrime(8)
        q = getPrime(8)

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 3
        d = int(gmpy2.invert(e, phi))
        break
    except ZeroDivisionError:
        pass

public_key = (e, n)
private_key = (d, n)

def enc(m, public_key):
    if isinstance(m, bytes):
        m = bytes_to_long(m)
    elif not isinstance(m, int):
        raise ValueError('Expects int or bytes.')

    return pow(m, public_key[0], public_key[1])

def dec(c, private_key):
    if isinstance(c, bytes):
        c = bytes_to_long(c)
    elif not isinstance(c, int):
        raise ValueError('Expects int or bytes.')
    
    return pow(c, private_key[0], private_key[1])

print(f'{public_key = }')
print(f'{private_key = }')

c = enc(42, public_key)
print(f'{c = }')
m = dec(c, private_key)
print(f'{m = }')