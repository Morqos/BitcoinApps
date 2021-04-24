# Original source code from "Mastering Bitcoin" by Andreas M. Antonopoulos

# DEPENDENCIES:
#       ecdsa:          pip install ecdsa
#       bitcoin         pip install bitcoin


# EXECUTION:
#
#       python .\gen_BTC_address_from_point_curve.py
# 
# Example output:
#       Secret:  0x3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6
#       Elliptic Curve point: (416373..., 163889...)
#       BTC public key uncompressed (HEX): 045c0de3b9...
#       BTC public key compressed (HEX): 025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec
#       BTC public address uncompressed:  1thMirt546nngXqyPEz532S8fLwbozud8
#       BTC public address compressed:  14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3


import ecdsa
import os
import hashlib
import bitcoin

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
    return byte_array


def get_point_pubkey_compressed(point):
    if (point.y() % 2) == 1:
        key = '03' + '%064x' % point.x()
    else:
        key = '02' + '%064x' % point.x()

    return key


def get_point_pubkey_uncompressed(point):
    key = ('04' + '%064x' % point.x() + '%064x' % point.y())
    return key



def main():

    # Generate a new private key: secret = random_secret()

    # Testing purposes, same private key as the one used in "Mastering Bitcoin"
    secret = hex(26563230048437957592232553826663696440606756685920117476832299673293013768870)
    print("Secret: ", secret)


    # Get the public key point.
    secretBase16 = int(secret, 16)
    point = secretBase16 * generator
    print("Elliptic Curve point:", point)


    publicKeyUncompressed = get_point_pubkey_uncompressed(point);
    publicKeyCompressed = get_point_pubkey_compressed(point);

    print("BTC public key uncompressed (HEX):", publicKeyUncompressed)
    print("BTC public key compressed (HEX):", publicKeyCompressed)


    btc_address_uncompressed = bitcoin.pubkey_to_address(publicKeyUncompressed);
    btc_address_compressed = bitcoin.pubkey_to_address(publicKeyCompressed)

    print("BTC public address uncompressed: ", btc_address_uncompressed);
    print("BTC public address compressed: ", btc_address_compressed );



if __name__ == "__main__":
    main()
