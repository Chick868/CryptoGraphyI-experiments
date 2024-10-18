from typing import Literal
import base64

print('### Challenge 1')

m = bytes.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
print(base64.b64encode(m).decode())

print()
print('### Challenge 2')

m1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
m2 = bytes.fromhex('686974207468652062756c6c277320657965')
res = bytes([x ^ y for x, y in zip(m1, m2)])
print(''.join(['%02x' % i for i in res]))

print()
print('### Challenge 3')

letter_frequency = {
    b'a': .08167, b'b': .01492, b'c': .02782, b'd': .04253,
    b'e': .12702, b'f': .02228, b'g': .02015, b'h': .06094,
    b'i': .06094, b'j': .00153, b'k': .00772, b'l': .04025,
    b'm': .02406, b'n': .06749, b'o': .07507, b'p': .01929,
    b'q': .00095, b'r': .05987, b's': .06327, b't': .09056,
    b'u': .02758, b'v': .00978, b'w': .02360, b'x': .00150,
    b'y': .01974, b'z': .00074, b' ': .15000
}

# use letter frequency
def single_byte_xor_crack(block):
    scores = []
    for ch in range(0, 0x100):
        res = [ch ^ i for i in block]
        scores.append({
            'key': ch,
            'message': res,
            'score' : sum([letter_frequency.get(bytes([i]), 0) for i in res])
        })
    return sorted(scores, key=lambda d: d['score'], reverse=True)[0]

c = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
score = single_byte_xor_crack(c)
print('key (hex): %s, message: %s' % ('%02x' % score['key'], bytes(score['message']).decode()))


print()
print('### Challenge 4')

with open('./4.txt', 'r') as f:
    lines = f.readlines()
    lines = [bytes.fromhex(line) for line in lines]


scores = []

for i in range(len(lines)):
    scores.append({
        'line_idx': i,
        'best_score': single_byte_xor_crack(lines[i])
    })

best_score = sorted(scores, key=lambda x: x['best_score']['score'], reverse=True)[0]
print('line %d, key (hex): %s' % (best_score['line_idx'], ''.join('%02x' % (best_score['best_score']['key']))))
print(bytes(best_score['best_score']['message']).decode())


print('### Challenge 5')

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

m = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'

key = b'ICE'

blocks, _ = div_blocks(m, len(key))
c = b''

for block in blocks:
    c += bytes([x ^ y for x, y in zip(key, block)])

c = c[:len(m)]
print(''.join(['%02x' % ch for ch in c]))