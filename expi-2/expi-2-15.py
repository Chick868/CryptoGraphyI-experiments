def printable(x: bytes):
    return all(map(lambda ch: 0x20 <= ch <= 0xfe, x))

def strip_tail(m: bytes):
    assert len(m) % 16 == 0
    possible_padding = m[-1]
    if possible_padding >= 16:
        if not printable(m):
            return None
        # no padding
        return m.decode()
    
    # there is a padding
    if m[-possible_padding:] != bytes([possible_padding]) * possible_padding:
        return None
    
    m = m[:-possible_padding]

    if not printable(m):
        return None
    
    return m.decode()

m = strip_tail(b'ICE ICE BABY\x04\x04\x04\x04')
if m:
    print(m)
else:
    print('Error padding!')