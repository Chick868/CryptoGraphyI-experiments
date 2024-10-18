c = bytes.fromhex('F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794')

target_char = [ord(','), ord('.'), ord(';'), ord('?'), ord('-'), ord(' ')]
target_char += list(range(ord('a'), ord('z') + 1)) + list(range(ord('A'), ord('Z') + 1))

def div_blocks(c: bytes, l: int):
    # padding with 0
    nblocks = (len(c) + (l - 1)) // l
    c = c.ljust(nblocks * l, b'\x00')

    blocks = []
    for i in range(nblocks):
        blocks.append(c[i * l : (i + 1) * l])
    return blocks, nblocks

def crack(c: bytes, length: int):
    key = b''
    blocks, nblocks = div_blocks(c, length)
    for pos in range(length):
        for ch in range(0, 0x100):
            valid = True
            for i in range(nblocks):
                if blocks[i][pos] != 0 and ch ^ blocks[i][pos] not in target_char:
                    valid = False
                    break
            if valid:
                key += bytes([ch])
                break
        if len(key) <= pos:
            return None
    return key
        

if __name__ == '__main__':
    for length in range(2, 14):
        key = crack(c, length)
        if key is not None:
            print(f'length: {length}, key found (hex): ' + ''.join(['%02X' % ch for ch in key]))
            print()
            m = b''
            blocks, nblocks = div_blocks(c, length)
            for i in range(nblocks):
                m += bytes([i ^ j for i, j in zip(blocks[i], key)])
            m = m[:len(c)]
            print(m.decode())
                