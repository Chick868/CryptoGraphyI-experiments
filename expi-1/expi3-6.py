import base64
from typing import Literal

white_list = []
white_list += [ord(i) for i in ',!.;?-\'\":/\n ']
white_list += list(range(ord('a'), ord('z') + 1)) + list(range(ord('A'), ord('Z') + 1))
white_list += list(range(ord('0'), ord('9') + 1))

letter_frequency = {
    b'a': .08167, b'b': .01492, b'c': .02782, b'd': .04253,
    b'e': .12702, b'f': .02228, b'g': .02015, b'h': .06094,
    b'i': .06094, b'j': .00153, b'k': .00772, b'l': .04025,
    b'm': .02406, b'n': .06749, b'o': .07507, b'p': .01929,
    b'q': .00095, b'r': .05987, b's': .06327, b't': .09056,
    b'u': .02758, b'v': .00978, b'w': .02360, b'x': .00150,
    b'y': .01974, b'z': .00074, b' ': .15000
}

def xor_str(a: bytes, b: bytes) -> bytes:
    if len(a) < len(b):
        return bytes([i ^ j for i, j in zip(a, b[:len(a)])])
    else: 
        return bytes([i ^ j for i, j in zip(a[:len(b)], b)])


def div_blocks(c: bytes, l: int, method: Literal['len', 'pos'] = 'len'):
    # padding with 0
    nblocks = (len(c) + (l - 1)) // l
    c = c.ljust(nblocks * l, b'\x00')
    blocks = []

    if method == 'len':
        for i in range(nblocks):
            blocks.append(c[i * l : (i + 1) * l])
    elif method == 'pos':
        for pos in range(l):
            blocks.append(bytes([c[i * l + pos] for i in range(nblocks)]))
        nblocks = l
    else: return None
    
    return blocks, nblocks

def distance(x: bytes, y: bytes):
    dst = 0
    xor_res = xor_str(x, y)
    for ch in xor_res:
        while ch != 0:
            dst += 1
            ch = ch & (ch - 1)
    return dst

def crack_key_length(c: bytes, nums: int = 4, lo: int = 2, hi: int = 40):
    dsts = []
    for l in range(lo, hi + 1):
        dst = []
        blocks, nblocks = div_blocks(c, l)
        for i in range(nblocks - 1):
            dst.append(distance(blocks[i], blocks[i + 1]) / l)
        dsts.append({'len': l, 'dst': sum(dst) / len(dst)})
    return sorted(dsts, key=lambda d: d['dst'])[:nums]


# # usr white list 
# def single_byte_xor_crack(blocks, pos):
#     for ch in range(0, 0x100):
#         valid = True
#         for c in blocks[pos]:
#             if c != 0 and c ^ ch not in white_list:
#                 valid = False
#                 break
#         if valid:
#             return ch
#     return None

# use letter frequency
def single_byte_xor_crack(blocks, pos):
    scores = []
    for ch in range(0, 0x100):
        res = [ch ^ i for i in blocks[pos]]
        scores.append({
            'key': ch,
            'score' : sum([letter_frequency.get(bytes([i]), 0) for i in res])
        })
    return sorted(scores, key=lambda d: d['score'], reverse=True)[0]['key']
    

def crack_with_length(c: bytes, l: int):
    key = b''
    # group by pos
    blocks, nblocks = div_blocks(c, l, method='pos')
    for pos in range(l):
        ch = single_byte_xor_crack(blocks, pos)
        if ch is None:
            return None
        key += bytes([ch])
    return key

def crack(c: bytes):
    dsts = crack_key_length(c)
    for d in dsts:
        l = d['len']
        key = crack_with_length(c, l)
        if key is not None:
            return key
    return None
        

if __name__ == '__main__':
    with open('./6.txt', 'rb') as f:
        c = f.read()
    c = base64.b64decode(c)
    key = crack(c)
    if key is not None:
        print(f'length {len(key)}, key found: {key}')
        print('\nmessage: ')
        m = b''
        blocks, nblocks = div_blocks(c, len(key))
        for i in range(nblocks):
            m += bytes([i ^ j for i, j in zip(blocks[i], key)])
        m = m[:len(c)]
        print(m.decode())