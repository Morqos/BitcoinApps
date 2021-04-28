# Very very simple implementation of the BIP-39 Bitcoin wallet standard
# 
# Original source code "mnemonic.py" from mnemonic/mnemonic.py
# from https://github.com/trezor/python-mnemonic


import bisect
import hashlib
import hmac
import itertools
import os
from typing import AnyStr, List, Sequence, TypeVar, Union
import unicodedata

wordlist = [];
PBKDF2_ROUNDS = 2048;

# Refactored code segments from <https://github.com/keis/base58>
def b58encode(v: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8

    string = ""
    while acc:
        acc, idx = divmod(acc, 58)
        string = alphabet[idx : idx + 1] + string
    return string







########################################################################################
######################################## BEGIN #########################################
################################## Get menmonic words ##################################
########################################################################################


def _get_directory():
    return os.path.join(os.path.dirname(__file__), "wordlist");


def setWordList(language):
    radix = 2048;
    with open( "%s/%s.txt" % (_get_directory(), language), "r", encoding="utf-8" ) as f:
        for w in f.readlines():
            wordlist.append(w.strip());
            
    if len(wordlist) != radix:
        raise ConfigurationError(
            "Wordlist should contain %d words, but it contains %d words." % (radix, len(wordlist))
        )

# This method returns a string which represents random bytes suitable for cryptographic use
def generate(strength: int = 128) -> str:
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError(
            "Strength should be one of the following [128, 160, 192, 224, 256], but it is not (%d)."
            % strength
        )
    return os.urandom(strength // 8);


def to_mnemonic(data: bytes) -> str:
    if len(data) not in [16, 20, 24, 28, 32]:
        raise ValueError(
            "Data length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d)."
            % len(data)
        )

    # zfill(len): adds zeros at the beginning of the string, until total length == len

    # 132 bits string - entropy :: first (entropy.length()/32) bits of Checksum
    checksum = hashlib.sha256(data).hexdigest()
    b = (
        bin(int.from_bytes(data, byteorder="big"))[2:].zfill(len(data) * 8)
        + bin(int(checksum, 16))[2:].zfill(256)[: len(data) * 8 // 32]
    )

    print("Entropy + checksum (first 4 bits): \n    " + b + "\n");
    
    result = []
    
    for i in range(len(b) // 11):
        idx = int(b[i * 11 : (i + 1) * 11], 2)
        result.append(wordlist[idx])

    result_phrase = " ".join(result)
    return result_phrase


########################################################################################
######################################### END ##########################################
################################## Get menmonic words ##################################
########################################################################################









########################################################################################
######################################## BEGIN #########################################
############################### Get seed and Master Key ################################
########################################################################################

def normalize_string(txt: AnyStr) -> str:
    if isinstance(txt, bytes):
        utxt = txt.decode("utf8")
    elif isinstance(txt, str):
        utxt = txt
    else:
        raise TypeError("String value expected")

    return unicodedata.normalize("NFKD", utxt)


def to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic = normalize_string(mnemonic)
    
    passphrase = normalize_string(passphrase)
    passphrase = "mnemonic" + passphrase
    passphrase_bytes = passphrase.encode("utf-8")

    mnemonic_bytes = mnemonic.encode("utf-8")
    
    stretched = hashlib.pbkdf2_hmac(
        "sha512", mnemonic_bytes, passphrase_bytes, PBKDF2_ROUNDS
    )
    return stretched[:64]


def to_hd_master_key(seed: bytes, testnet: bool = False) -> str:
    if len(seed) != 64:
        raise ValueError("Provided seed should have length of 64")

    # Compute HMAC-SHA512 of seed
    seed = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()

    # Serialization format can be found at: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
    xprv = b"\x04\x88\xad\xe4"  # Version for private mainnet
    if testnet:
        xprv = b"\x04\x35\x83\x94"  # Version for private testnet
    xprv += b"\x00" * 9  # Depth, parent fingerprint, and child number
    xprv += seed[32:]  # Chain code
    xprv += b"\x00" + seed[:32]  # Master key

    # Double hash using SHA256
    hashed_xprv = hashlib.sha256(xprv).digest()
    hashed_xprv = hashlib.sha256(hashed_xprv).digest()

    # Append 4 bytes of checksum
    xprv += hashed_xprv[:4]

    # Return base58
    return b58encode(xprv)


########################################################################################
######################################### END ##########################################
############################### Get seed and Master Key ################################
########################################################################################







def main():

    setWordList("english")
    
    # generates randomly the string of bytes
    byteString = generate();
    print("The randomly generated byte string is: \n    " + str(byteString) + "\n");

    mnemonicWords = to_mnemonic(byteString)
    print("The mnemonic words generated are: \n    " + mnemonicWords + "\n");

    seedGenerated = to_seed(mnemonicWords);
    print("The seed generated is: \n   " + str(seedGenerated) + "\n");

    masterKey = to_hd_master_key(seedGenerated);
    print("The master key generated is: \n   " + masterKey + "\n");



if __name__ == "__main__":
    main()
