# Original source code from "Mastering Bitcoin" by Andreas M. Antonopoulos and
# open_wallet.py by davidbarton: https://gist.github.com/davidbarton/5312189#file-open_wallet-py-L1

# Dependencies:
#       ecdsa:          pip install ecdsa
#       pycryptodome:   pip install pycryptodome

#       python .\gen_BTC_address_from_point_curve.py
# 
# Example output:
#       Secret:  114061222202366649671227529824392808850943239518307014538914206129784427369312
#       Elliptic Curve point: (77157914653301193822618917257536926206048290956350968644684726692613576043223,23134012828889986758439068916210517134330966611504246855273296678132029683708)
#       BTC public key (HEX): 04aa95d5040ff96299356e3028d872d91d0221ccb459d6b40a4db6fcc536c9aad733256322c0004bc8fa10e24f86214637a961c3ce8625206369260054b04577fc
#       BTC public address:  1fDvth9hUPHdqA9XsbVACxDMdFrzj8ZAVPbskkw1xeKcL3qNBb9HmadYGLzZfAfpWqKfeZCZqrUYif82EHZ99G4XNuk


import ecdsa
import os
from Crypto.Hash import RIPEMD160
import hashlib

# Prime number of field
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# private_key in [1, _r]. Source: https://en.bitcoin.it/wiki/Allprivatekeys
#       _r = max num for private key
#       _r is in Hexadecimal
#       _r in Decimal = 115792089237316195423570985008687907852837564279074904382605163141518161494337
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_a = 0x0000000000000000000000000000000000000000000000000000000000000000

_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)
generator_secp256k1 = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)

# Curve Object Identifier for Curve Alias "secp256k1"
oid_secp256k1 = (1, 3, 132, 0, 10)


SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1)


ec_order = _r
curve = curve_secp256k1
generator = generator_secp256k1



def random_secret():
    # 32 Bytes -> 32 * 8 bits = 2^5 * 2^3 bits = 2^8 bits = 256 bits randomly chosen
    byte_array = (os.urandom(32)).hex()

    return int(byte_array,16) # Returs the randomly generated number in base 16


def get_point_pubkey_compressed(point):
    if (point.y() % 2) == 1:
        key = '03' + '%064x' % point.x()
    else:
        key = '02' + '%064x' % point.x()

    return key


def get_point_pubkey_uncompressed(point):
    key = ('04' + '%064x' % point.x() + '%064x' % point.y())
    return key





################################################################################################################
########################## Functions to transition from PUBLIC KEY to BITCOIN ADDRESS ##########################
################################################################################################################


addrtype = 0
__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


def Hash(data):
    return hashlib.sha256(hashlib.sha256(data.encode('utf-8')).digest()).digest()


def public_key_to_bc_address(public_key):
	h160 = hash_160(public_key)
	return hash_160_to_bc_address(h160)


def hash_160(public_key):
    try:
        md = hashlib.new('ripemd160')
        md.update(hashlib.sha256(public_key.encode('utf-8')).digest())
        return md.digest()
    except:
        md = RIPEMD160.new(hashlib.sha256(public_key.encode('utf-8')).digest())
        return md.digest()


def hash_160_to_bc_address(h160):
	vh160 = chr(addrtype) + str(h160)
	h = Hash(vh160)
	addr = vh160 + str(h[0:4])
	return b58encode(addr)


def b58encode(v):
    # encode v, which is a string of bytes, to base58
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

	# Bitcoin does a little leading-zero-compression: leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result


################################################################################################################
########################## Functions to transition from PUBLIC KEY to BITCOIN ADDRESS ##########################
################################################################################################################





def main():
    # Generate a new private key.
    secret = random_secret()
    print("Secret: ", secret)


    # Get the public key point.
    point = secret * generator
    print("Elliptic Curve point:", point)


    publicKey = get_point_pubkey_uncompressed(point);
    print("BTC public key (HEX):", publicKey)


    # Given the point (x, y) we can create the object using:
    point1 = ecdsa.ellipticcurve.Point(curve, point.x(), point.y(), ec_order)
    assert(point1 == point)


    BTC_addrres = public_key_to_bc_address(publicKey)
    print("BTC public address: ", BTC_addrres);



if __name__ == "__main__":
    main()