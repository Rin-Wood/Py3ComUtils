from typing import Union
from Crypto.Cipher import AES
from hashlib import new as hashnew
from Crypto.Protocol.KDF import PBKDF2
from cxxtea import decrypt as decxxtea
from crijndael import decrypt as daes256
from Crypto.Util.Padding import unpad as UNPAD
from Crypto.Util.Counter import new as AesCounter
from numpy import uint8, frombuffer as buffer, tile
from Crypto.Hash import (
    BLAKE2b, BLAKE2s, cSHAKE128, cSHAKE256, CMAC, HMAC, keccak, KangarooTwelve, KMAC128, KMAC256, MD2, 
    MD4, MD5, Poly1305, RIPEMD, RIPEMD160, SHA,  SHA1, SHA224, SHA256, SHA384, SHA3_224, SHA3_256, SHA3_384,
    SHA3_512, SHA512,  SHAKE128, SHAKE256, TurboSHAKE128, TupleHash128, TupleHash256, TurboSHAKE256
)

# AES

HASH_ALGORITHMS = {
    'blake2b': BLAKE2b, 'blake2s': BLAKE2s, 'cshake128': cSHAKE128, 'cshake256': cSHAKE256, 'cmac': CMAC, 'hmac': HMAC, 'keccak': keccak, 'kangarootwelve': KangarooTwelve,
    'kmac128': KMAC128, 'kmac256': KMAC256, 'md2': MD2, 'md4': MD4, 'md5': MD5, 'poly1305': Poly1305, 'ripemd': RIPEMD, 'ripemd160': RIPEMD160, 'sha': SHA, 'sha1': SHA1,
    'sha224': SHA224, 'sha256': SHA256, 'sha384': SHA384, 'sha3_224': SHA3_224, 'sha3_256': SHA3_256, 'sha3_384': SHA3_384, 'sha3_512': SHA3_512, 'sha512': SHA512,
    'shake128': SHAKE128, 'shake256': SHAKE256, 'turboSHAKE128': TurboSHAKE128, 'turboSHAKE256': TurboSHAKE256, 'tuplehash128': TupleHash128, 'tuplehash256': TupleHash256,
}

def KeyPBKDF1(password:Union[str, bytes], salt:Union[str, bytes], keylen: int = 16, count: int = 100, hashAlgorithm: str = 'sha1') -> bytes:
    """Derives a cryptographic key using the PBKDF1 (Password-Based Key Derivation Function 1) algorithm

    PBKDF1 applies iterative hashing on the input password and salt to derive a fixed-length key.
    This implementation allows the use of different hashing algorithms, such as SHA-1, MD5, etc

    Args
    ----
    password : Union[str, bytes]
        The input password, either as a string or bytes
    salt : Union[str, bytes]
        The salt value, used to randomize the key, either as a string or bytes
    keylen : int
        The desired length of the derived key, default is 16 bytes
    count : int
        The number of hash iterations to perform, default is 100
    hashAlgorithm : str
        The hash algorithm to use (e.g., 'sha1', 'md5'), default is 'sha1'
    
    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import KeyPBKDF1

    # Derive a 16-byte key using 'sha1' as the hash algorithm
    key = KeyPBKDF1('password123', 'somesalt', keylen=16, count=100, hashAlgorithm='sha1')
    ```
    """
    index, count = 1, count - 2
    hashval = hashnew(hashAlgorithm, (password.encode('utf-8') if isinstance(password, str) else password) + (salt.encode('utf-8') if isinstance(salt, str) else salt)).digest()
    for _ in range(count):
        hashval = hashnew(hashAlgorithm, hashval).digest()
    hashder = hashnew(hashAlgorithm, hashval).digest()
    while len(hashder) < keylen:
        hashder += hashnew(hashAlgorithm, str(index).encode('utf-8') + hashval).digest()
        index += 1
    return hashder[:keylen]

def KeyPBKDF2(password: Union[str, bytes], salt: Union[str, bytes], keylen:int = 32, count = 100, hashAlgorithm: str = 'sha1') -> bytes:
    """Derives a cryptographic key using the PBKDF2 (Password-Based Key Derivation Function 2) algorithm

    PBKDF2 applies HMAC (Hash-based Message Authentication Code) with a specified hash algorithm
    to the password and salt iteratively, producing a cryptographic key of the desired length.
    The function allows the use of various hash algorithms (e.g., 'sha1', 'md5')

    Args
    ----
    password : Union[str, bytes]
        The input password, either as a string or bytes
    salt : Union[str, bytes]
        The salt value, used to randomize the key, either as a string or bytes
    keylen : int
        The desired length of the derived key, default is 16 bytes
    count : int
        The number of hash iterations to perform, default is 100
    hashAlgorithm : str
        The hash algorithm to use (e.g., 'sha1', 'md5'), default is 'sha1'
    
    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import KeyPBKDF2

    # Derive a 16-byte key using 'sha1' as the hash algorithm
    key = KeyPBKDF2('password123', 'somesalt', keylen=16, count=100, hashAlgorithm='sha1')
    ```
    """
    if isinstance(password, str): password = password.encode('utf-8')
    if isinstance(salt, str): salt = salt.encode('utf-8')
    return PBKDF2(password, salt, count=count, dkLen=keylen, hmac_hash_module=HASH_ALGORITHMS[hashAlgorithm.lower()])

def KeyEVPKDF(password: Union[str, bytes], salt:bytes, keySize: int = 32, ivSize: int = 16, iterations: int = 1, hashAlgorithm: str = 'md5') -> tuple[bytes, bytes]:
    """Derives a cryptographic key and IV using the EVP Key Derivation Function (KDF)

    EVP KDF uses iterative hashing to derive a key and an initialization vector (IV) from the password and salt.
    The result is a concatenation of the key and IV, which is split to obtain both values

    Args
    ----
    password : Union[str, bytes]
        The input password, provided either as a string or bytes. If a string is provided, it will be encoded as UTF-8 bytes
    salt : bytes
        A byte string used to randomize the key and IV generation. This ensures uniqueness
    keySize : int
        The desired length of the key in bytes. Default is 32 bytes
    ivSize : int
        The desired length of the initialization vector (IV) in bytes. Default is 16 bytes
    iterations : int
        The number of hashing iterations to perform. Default is 1. Increasing this value makes the key derivation slower but more secure
    hashAlgorithm : str
        The hash algorithm to use (e.g., 'md5', 'sha1'). Default is 'md5'

    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import KeyEVPKDF

    # Derive a 32-byte key and 16-byte iv using 'md5' as the hash algorithm
    key, iv = KeyEVPKDF('password123', b'somesalt', keySize=32, ivSize=16, iterations=1000, hashAlgorithm='md5')
    ```
    """
    if isinstance(password, str): password = password.encode('utf-8')
    if isinstance(salt, str): salt = salt.encode('utf-8')

    final_length = keySize + ivSize
    key_iv = b''
    block = None
        
    while len(key_iv) < final_length:
        hasher = hashnew(hashAlgorithm)
        if block:
            hasher.update(block)
        hasher.update(password)
        hasher.update(salt)
        block = hasher.digest()
        for _ in range(1, iterations):
            block = hashnew(hashAlgorithm, block).digest()
        key_iv += block
        
    key, iv = key_iv[:keySize], key_iv[keySize:final_length]
    return key, iv

def AESCBCBytes(data: bytes, key: bytes, iv: bytes, unpad: int) -> bytes:
    """Decrypts data using AES in CBC (Cipher Block Chaining) mode

    This function uses AES in CBC mode to decrypt the provided data using the given key and initialization vector (IV).
    If padding is present, the function removes it

    Args
    ----
    data : bytes
        The encrypted data to be decrypted
    key : bytes
        The key used for AES decryption
    iv : bytes
        The initialization vector used for AES in CBC mode
    unpad : int
        If provided, this value specifies the padding length that should be removed after decryption.
        If `None`, the data is returned as-is without unpadding

    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import AESCBCBytes
    data = AESCBCBytes(encrypted_data, key, iv, unpad=16)
    ```
    """
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    if unpad is None:
        return dec
    return UNPAD(dec, unpad)

def AESECBBytes(data: bytes, key: bytes, unpad: int) -> bytes:
    """Decrypts data using AES in ECB (Electronic Codebook) mode

    This function uses AES in ECB mode to decrypt the provided data using the given key.
    ECB mode processes each block of plaintext independently, which can lead to security vulnerabilities.
    If padding is present, the function removes it based on the specified unpadding length

    Args
    ----
    data : bytes
        The encrypted data to be decrypted
    key : bytes
        The key used for AES decryption
    unpad : int
        If provided, this value specifies the padding length that should be removed after decryption.
        If `None`, the data is returned as-is without unpadding

    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import AESECBBytes
    data = AESECBBytes(encrypted_data, key, unpad=16)
    ```
    """
    dec = AES.new(key, AES.MODE_ECB).decrypt(data)
    if unpad is None:
        return dec
    return UNPAD(dec, unpad)

def AESPBKDF1Bytes(data: bytes, password: Union[str, bytes], salt: Union[str, bytes], count: int = 100, keylen: int = 16, nbits: int = 64, suffix: bytes = b'\x00' * 8, endian: str = 'little', hashAlgorithm: str = 'sha1') -> bytes:
    """AES - CTR - PBKDF1 decryption

    Args
    ----
    data : bytes
        The encrypted data to be decrypted
    password : bytes
        The password required for decryption
    count : int
        Key Rounds, default is 100
    keylen : int
        Set the length of the key, default value is 16
    nbits : int
        Length of the desired counter value, in bits. It must be a multiple of 8
    suffix : bytes
        The constant postfix of the counter block. By default, no suffix is used
    endian : str
        little (default) or big
    hashAlgorithm : str
        Specifies the hash type used by the key, default is 'sha1'

    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import AESPBKDF1Bytes
    data = AESPBKDF1Bytes(encrypted_data, password, salt)
    ```
    """
    key = KeyPBKDF1(password, salt, keylen, count, hashAlgorithm)
    return AES.new(key, AES.MODE_CTR, counter=AesCounter(nbits, suffix=suffix, little_endian=endian == 'little')).decrypt(data)

# XOR
def XorBytes(data:bytes, key:bytes) -> bytes:
    """Performs a bitwise XOR operation between the data and the key

    This function applies the XOR operation on the provided data and key bytes.
    If the key is a single byte, it XORs each byte of the data with that key byte.
    If the key is longer, it repeats the key to match the length of the data

    Args
    ----
    data : bytes
        The data to be XORed. This should be a byte sequence
    key : bytes
        The key used for the XOR operation. The key can be a single byte or longer

    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import XorBytes
    result = XorBytes(data, b'\\x01')
    ```
    """
    darr, karr = buffer(data, dtype=uint8), buffer(key, dtype=uint8)
    klen = karr.size

    if klen == 1: return (darr ^ karr).tobytes()
    else:
        dlen = darr.size
        return (darr ^ tile(karr, (dlen // klen) + 1)[:dlen]).tobytes()

def xxtea(data:bytes, sign:bytes, key:bytes, delta: int = 0x9e3779b9, delend: int = 1, mode: bool = True) -> bytes:
    """ Decrypt xxtea

    Args
    ----
    data : bytes
        The encrypted data to be decrypted
    sign : bytes
        enc sign
    key : bytes
        The key required for decryption
    delta : int
        set delta | Default 0x9e3779b9
    delend : int
        Remove extra bytes | Default 1
    mode : bool
        check sign | Default True

    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import XxteaBytes
    result = XxteaBytes(data, b'aabb', b'aaaaaaaaaaaaaaaa')
    ```
    """
    if mode:
        if not data.startswith(sign): return
        data = data[len(sign):]
    key = key.ljust(16, b'\x00')
    decd = decxxtea(data, b'', key, delta, delend)
    return decd

def aes256(data: bytes, key: bytes, iv: bytes, blocksize: int = 128, keysize: int = 128, mode: int = 0) -> bytes:
    """Decrypt AES-256

    Args
    ----
    data : bytes
        The encrypted data to be decrypted
    key : bytes
        The key used for AES decryption
    iv : bytes
        The initialization vector used for AES in CBC mode
    blocksize : int
        blocksize | Default 128
    keysize : int
        keysize | Default 128
    mode : int
        0 - CBC, 1 - ECB | Default 0

    Example
    -------
    ```python
    from Py3ComUtils.Decrypt import aes256
    data = aes256(encrypted_data, key, iv, blocksize=256, keysize=256, mode=0)
    ```
    """
    return daes256(data, key, iv, blocksize, keysize, mode)
