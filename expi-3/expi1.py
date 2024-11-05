import gmpy2

p = 1009
q = 3643
phi_n = (p - 1) * (q - 1)

x = []
best = 1 << 64

for e in range(2, phi_n):
    if gmpy2.gcd(e, phi_n) == 1:
        numP = (gmpy2.gcd(p - 1, e - 1) + 1) * (gmpy2.gcd(q - 1, e - 1) + 1)
        if best == numP:
            x.append(e)
        elif best > numP:
            best = numP
            x = [e]

print(x)
print(sum(x))
print(best)
