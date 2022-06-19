from Cryptodome.Cipher import AES

def encrypt_ecb(key, pt, iv=None):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(pt)

def decrypt_ecb(key, ct, iv=None):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(ct)

def print_bytes(bts):
    for i in range(len(bts)//8):
        print('    ' + f', '.join([f'0x{b:02x}' for b in bts[8*i:8*(i+1)]]) + ',')
        pass
    return

def print_testvectors(enc_f, key, pt, iv=None):
    ct = enc_f(key, pt, iv)
    ver = '128'
    mod = 'ecb'
    if len(key) == 24:
        ver = '192'
    elif len(key) == 32:
        ver = '256'
    print(f'unsigned char key{ver}{mod}[{len(key)}] = {{')
    print_bytes(key)
    print('};')
    print(f'unsigned char ptx{ver}{mod}[{len(pt)}] = {{')
    print_bytes(pt)
    print('};')
    print(f'unsigned char ctx{ver}{mod}[{len(ct)}] = {{')
    print_bytes(ct)
    print('};')
    return

if __name__ == '__main__':
    FIPS197 = False
    if FIPS197:
        iv      = bytes.fromhex('FFEEDDCCBBAA99887766554433221100')
        pt      = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
        key128  = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        key192  = bytes.fromhex('000102030405060708090A0B0C0D0E0F1011121314151617')
        key256  = bytes.fromhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
        pass
    else:
        import os
        iv      = os.urandom(16)
        #Change Size here for different input choices
        pt      = os.urandom(1024*1024)
        key128  = os.urandom(16)
        key192  = os.urandom(24)
        key256  = os.urandom(32)
        pass
    print_testvectors(encrypt_ecb, key128, pt, None)
    print_testvectors(encrypt_ecb, key192, pt, None)
    print_testvectors(encrypt_ecb, key256, pt, None)
    pass
