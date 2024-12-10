from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
import math
import gmpy2

entries = []
ans = [-1 for _ in range(21)]

for i in range(21):
    with open(f'./frames/Frame{i}', 'r') as f:
        N = bytes_to_long(bytes.fromhex(f.read(256)))
        e = bytes_to_long(bytes.fromhex(f.read(256)))
        c = bytes_to_long(bytes.fromhex(f.read(256)))
        entries.append({'N': N, 'e': e, 'c': c, 'idx': i})


print(f"\n\n#{' Common Modulus Attack '.center(70, '=')}#")

def exgcd(a, b):
    if b == 0:
        return 1, 0
    x, y = exgcd(b, a % b)
    return y, x - a // b * y

def CMA(n, e1, c1, e2, c2):
    x, y = exgcd(e1, e2)
    return (pow(c1, x, n) * pow(c2, y, n)) % n

for en1 in entries:
    for en2 in entries[en1['idx'] + 1:]:
        if en1['N'] == en2['N']:
            m = CMA(en1['N'], en1['e'], en1['c'], en2['e'], en2['c'])
            ans[en1['idx']] = m
            ans[en2['idx']] = m
            m = long_to_bytes(m)[-8:]
            print('[+] CMA exists between {} and {}: {}'.format(en1['idx'], en2['idx'], m))

print(f"\n\n#{' Broadcast Attack '.center(70, '=')}#")

def CRT(a, m):
    M = math.prod(m)
    Mi = [M // x for x in m]
    Mi_inv = [inverse(x, y) for x, y in zip(Mi, m)]
    return sum([x * y * z for x, y, z in zip(a, Mi, Mi_inv)]) % M

def broadcast_attack(c, n, e):
    _c = CRT(c, n)
    m, flag = gmpy2.iroot(_c, e)
    if flag:
        return m
    return None

target1 = []
target2 = []
for i in range(len(entries)):
    if entries[i]['e'] == 5:
        target1.append(i)
    elif entries[i]['e'] == 3:
        target2.append(i)

m1 = broadcast_attack(
    [entries[x]['c'] for x in target1],
    [entries[x]['N'] for x in target1], 5
)

m2 = broadcast_attack(
    [entries[x]['c'] for x in target2],
    [entries[x]['N'] for x in target2], 3
)


if m1:
    for i in target1:
        ans[i] = m1
    m1 = long_to_bytes(m1)[-8:]
    print('[+] Broadcast Attack under base {} exists in {}: {}'.format(5, target1, m1))
else:
    print('[-] Broadcast Attack under base {} does not exist'.format(5))
if m2:
    for i in target1:
        ans[i] = m2
    m2 = long_to_bytes(m2)[-8:]
    print('[+] Broadcast Attack under base {} exists in {}: {}'.format(3, target2, m2))
else:
    print('[-] Broadcast Attack under base {} does not exist'.format(3))


print(f"\n\n#{' Common Factor Attack '.center(70, '=')}#")

def CFA(en1, en2):
    c1, e1, n1 = en1['c'], en1['e'], en1['N']
    c2, e2, n2 = en2['c'], en2['e'], en2['N']
    p = math.gcd(n1, n2)
    q1, q2 = n1 // p, n2 // p
    m1 = pow(c1, inverse(e1, (p - 1) * (q1 - 1)), n1)
    m2 = pow(c2, inverse(e2, (p - 1) * (q2 - 1)), n2)
    return m1, m2

for en1 in entries:
    for en2 in entries[en1['idx'] + 1:]:
        if en1['N'] != en2['N'] and math.gcd(en1['N'], en2['N']) != 1:
            m1, m2 = CFA(en1, en2)
            ans[en1['idx']] = m1
            ans[en2['idx']] = m2
            m1 = long_to_bytes(m1)[-8:]
            m2 = long_to_bytes(m2)[-8:]
            print('[+] CMA exists between {} and {}: {}'.format(en1['idx'], en2['idx'], m))
            print('    {}: {}'.format(en1['idx'], m1))
            print('    {}: {}'.format(en2['idx'], m2))

print(f"\n\n#{' Pollard p-1 '.center(70, '=')}#")

def Pollard_p_1(c, e, n, upper_bound):
    B = math.factorial(upper_bound)
    p = math.gcd(pow(2, B, n) - 1, n)
    if p == 1:
        return None
    q = n // p
    assert p * q == n
    return pow(c, inverse(e, (p - 1) * (q - 1)), n)

for en in entries:
    res = Pollard_p_1(en['c'], en['e'], en['N'], 10000)
    if res:
        print('[+] Pollard p-1 exists in {}: {}'.format(en['idx'], long_to_bytes(res)[-8:]))
        ans[en['idx']] = res

print(f"\n\n#{' Summary '.center(70, '=')}#")
for i, x in enumerate(ans):
    print('frame {}: {}'.format('%2d' % i, '*' * 8 if x == -1 else long_to_bytes(x)[-8:].decode()))
