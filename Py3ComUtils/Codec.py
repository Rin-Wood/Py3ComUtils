from gzip import open as gzipopen
from bz2 import decompress as dbz2
from hashlib import new as hashnew
from lzma import decompress as dlzma
from xmltodict import parse as xmlparse
from sqlite3 import connect as sqconnect
from msgpack.ext import ExtType as msgext
from brotli import decompress as brotlidec
from typing import Union, Tuple, List, Dict
from lz4.block import decompress as dlz4block
from lz4.frame import decompress as dlz4frame
from json import loads as cjson, dumps as djson
from msgpack.fallback import Unpacker as msgupk
from zlib import MAX_WBITS as zlibmax, decompress as dzlib
from msgpack import packb as msgpack, unpackb as msgunpackb
from base64 import b64decode as dbase64, b64encode as ebase64
from blackboxprotobuf import protobuf_to_json, decode_message, encode_message

def ctext(data: bytes, encoding: str = '') -> str:
    """Converts bytes to a string using the specified encoding

    Args:
        data (bytes): The byte data to convert
        encoding (str, optional): The encoding to use for conversion. If not provided, UTF-8 is used
    """
    if encoding:
        try:
            return data.decode(encoding)
        except:
            pass
    try:
        return data.decode('utf-8')
    except:
        return data.decode('utf-8-sig')

def cline(data: Union[str, bytes], encoding: str = '') -> list[str]:
    """Splits the input string or bytes into lines

    Args:
        data (Union[str, bytes]): The input data, either a string or bytes
        encoding (str, optional): The encoding to use if the input is bytes. Default is UTF-8
    """
    if isinstance(data, str):
        return data.splitlines()
    else:
        return ctext(data, encoding).splitlines()

def dxml(data: Union[str, bytes]) -> dict:
    """Parses XML data from a string or bytes and returns it as a dictionary

    Args:
        data (Union[str, bytes]): The XML data to parse
    """
    if isinstance(data, str):
        return xmlparse(data)
    else:
        return xmlparse(ctext(data))

def dlz4b(data: bytes, size: int = -1) -> bytes:
    """Decompresses LZ4 block data

    Args:
        data (bytes): The LZ4 compressed data
        size (int, optional): The expected uncompressed size. Default is -1
    """
    return dlz4block(data) if size == -1 else dlz4block(data, uncompressed_size=size)

def dlz4f(data: bytes) -> bytes:
    """Decompresses LZ4 frame data

    Args:
        data (bytes): The LZ4 compressed frame data
    """
    return dlz4frame(data)

def byteint(data: bytes, endian: str = 'little', signed: bool = False) -> int:
    """Convert a byte sequence into an integer

    Args:
        data (bytes): The byte sequence to be converted into an integer
        endian (str, optional): The byte order used to interpret the byte sequence, Can be either 'little' (default) or 'big'
        signed (bool, optional): Indicates whether the integer is signed, If True, the byte sequence will be interpreted as a signed integer, Defaults to False
    """
    return int.from_bytes(data, byteorder=endian, signed=signed)

def intbyte(number: int, blen: int = 4, endian: str = 'little', signed: bool = False) -> bytes:
    """Convert an integer into a byte sequence

    Args:
        number (int): The integer to be converted into bytes
        blen (int, optional): The length of the byte sequence. Defaults to 4 bytes
        endian (str, optional): The byte order to use ('little' for little-endian or 'big' for big-endian), Defaults to 'little'
        signed (bool, optional): Whether the integer is signed or unsigned, If True, the integer is interpreted as a signed integer. Defaults to False
    """
    return number.to_bytes(blen, byteorder=endian, signed=signed)

def dgzip(fp: Union[str, bytes]) -> bytes:
    """Decompresses gzip data from a file or byte stream

    Args:
        fp (Union[str, bytes]): The file path or byte stream to decompress
    """
    try:
        if isinstance(fp, str):
            with gzipopen(fp, 'rb') as file:
                return file.read()
        else:
            return dzlib(fp, 16 + zlibmax)
    except:
        return fp

def dbrotli(data: bytes) -> bytes:
    """Decompresses Brotli data

    Args:
        data (bytes): The Brotli compressed data
    """
    try:
        return brotlidec(data)
    except:
        return data

def ddeflate(data: bytes) -> bytes:
    """Decompresses deflate (zlib) data

    Args:
        data (bytes): The deflate compressed data
    """
    try:
        return dzlib(data, -zlibmax)
    except:
        try:
            return dzlib(data, zlibmax)
        except:
            try:
                return dzlib(data, 16 + zlibmax)
            except:
                return data

class msgundata:
    @classmethod
    def unpackmsg(cls, data: bytes, strict: bool = False) -> Tuple[object, int]:
        undata = msgupk(None, max_buffer_size=len(data), strict_map_key=strict)
        undata.feed(data)
        temp = undata._unpack()
        return temp, undata._buff_i

    @classmethod
    def lz4dec(cls, data: bytes) -> bytes:
        size = len(data) * 2
        while True:
            try:
                return dlz4b(data, size)
            except:
                size <<= 1

    @classmethod
    def unpack(cls, data: bytes, strict: bool = False) -> Union[List[object], object, Dict[object, object]]:
        results = []
        pos = 0
        dlen = len(data)
        while pos < dlen:
            obj, rlen = cls.unpackmsg(data[pos:], strict)
            pos += rlen
            if type(obj) is msgext and obj.code == 99:
                unlen, readlen = cls.unpackmsg(obj.data, strict)
                undata = cls.lz4dec(obj.data[readlen:])
                undatalen = len(undata)
                assert undatalen == unlen
                unobj, readlen = cls.unpackmsg(undata, strict)
                assert readlen == undatalen
                results.append(unobj)
            elif isinstance(obj, list) and len(obj) > 0:
                if type(obj[0]) is msgext and obj[0].code == 98:
                    unls, unlenls, count, pos2, objb = [], [], len(obj) - 1, 0, obj[0].data
                    for _ in range(count):
                        temp, rlen = cls.unpackmsg(objb[pos2:], strict)
                        pos2 += rlen
                        unlenls.append(temp)
                    assert pos2 == len(objb)
                    for i in range(count):
                        temp = cls.lz4dec(obj[i + 1])
                        assert len(temp) == unlenls[i]
                        unls.append(temp)
                    undata = b''.join(unls)
                    unobj, rlen = cls.unpackmsg(undata, strict)
                    assert rlen == len(undata)
                    results.append(unobj)
                else:
                    results.append(obj)
            else:
                results.append(obj)
        return results

def dmsg(data: bytes, strict: bool = False) -> Union[List[object], object, Dict[object, object]]:
    """Unpacks and processes msgpack encoded data

    Args:
        data (bytes): The msgpack encoded data
        strict (bool): strict_map_key | Default False
    """
    objs = msgundata.unpack(data, strict)
    return objs[0] if len(objs) == 1 else objs

def rproto(data: bytes) -> dict:
    """Parses protobuf data and returns it as a JSON-compatible dictionary

    Args:
        data (bytes): The protobuf data to parse
    """
    pjson = protobuf_to_json(data)[0]
    return cjson(pjson)

class Proto:
    """A class for handling protobuf message encoding and decoding operations
    
    Args
    ----
    message : Union[str, bytes]
        - The input protobuf message. Can be a base64 encoded string or a raw byte message

    Properties
    ----------
    **repack** : _bytes_
        - Encodes the current message dictionary back to a protobuf byte array

    **repackbase64** : _bytes_
        - Encodes the current message dictionary back to a base64-encoded byte array

    **repackt** : _str_
        - Encodes the current message dictionary back to a base64-encoded string

    **json** : _dict_
        - Converts the current protobuf message to a JSON-compatible dictionary

    Examples
    --------
    ```python
    from Py3ComUtils.FileHandler import Proto
    
    # Example usage:
    message_bytes = b'...'  # Some protobuf byte message
    proto = Proto(message_bytes)
    proto.dict['0'] = ''  # Modify the message dictionary
    proto_dict = proto.json  # Get the protobuf message as a JSON-like dictionary
    base64_message = proto.repackbase64  # Repack the message into base64-encoded bytes
    protobuf_bytes = proto.repack  # Repack the message into raw protobuf bytes
    ```
    """
    def __init__(self, message: Union[str, bytes]):
        """Initializes the Proto class with a Base64-encoded string or byte message

        Args:
            message (Union[str, bytes]): The input protobuf message
        """
        self.data = dbase64(message) if isinstance(message, str) else message
        self.dict, self.type = decode_message(self.data)

    @property
    def repack(self) -> bytes:
        """Re-encodes the parsed protobuf message into bytes"""
        return encode_message(self.dict,self.type)

    @property
    def repackbase64(self) -> bytes:
        """Re-encodes the parsed protobuf message into Base64-encoded bytes"""
        return ebase64(encode_message(self.dict,self.type))

    @property
    def repackt(self) -> str:
        """Re-encodes the parsed protobuf message into a Base64-encoded string"""
        return ctext(ebase64(encode_message(self.dict,self.type)))

    @property
    def json(self) -> dict:
        """Returns the protobuf message as a JSON-compatible dictionary"""
        return cjson(protobuf_to_json(self.data)[0])

class c2duuid:
    BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    HEX = '0123456789abcdef'

    @classmethod
    def cuuid(cls, src: str) -> str:
        pos = src.find('@')
        cut = src[:pos] if pos != -1 else src
        if len(cut) != 22: return src
        uuid = ''
        for i in range(2, 22, 2):
            l = cls.BASE64.find(cut[i])
            r = cls.BASE64.find(cut[i + 1])
            if l == -1 or r == -1: return src
            uuid += cls.HEX[l >> 2] + cls.HEX[((l & 3) << 2) | (r >> 4)] + cls.HEX[r & 0xF]
        return f'{cut[:2]}{uuid[:6]}-{uuid[6:10]}-{uuid[10:14]}-{uuid[14:18]}-{uuid[18:]}'

    @classmethod
    def euuid(cls, src: str) -> str:
        pos = src.find('@')
        cut = src[:pos] if pos != -1 else src
        if len(cut) != 36: return src
        cut = cut.replace('-', '')
        uuid = cut[:2]
        for i in range(2, 32, 3):
            l = cls.HEX.find(cut[i])
            m = cls.HEX.find(cut[i + 1])
            r = cls.HEX.find(cut[i + 2])
            if l == -1 or m == -1 or r == -1: return src
            uuid += cls.BASE64[(l << 2) | (m >> 2)] + cls.BASE64[((m & 3) << 4) | r]
        return uuid

def gethash(value:Union[str, bytes], hashAlgorithm:str = 'md5', mode: str = 'hex') -> Union[str, bytes]:
    hashv = hashnew(hashAlgorithm, (value.encode('utf-8') if isinstance(value, str) else value))
    return hashv.digest() if mode == 'bytes' else hashv.hexdigest()
