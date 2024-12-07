from typing import Union
from zipfile import ZipFile
from struct import unpack as UnPack
from PIL.Image import frombytes, Image
from .Codec import cline, dgzip, ctext
from io import BytesIO, BufferedReader
from json import load as jsonload, dump as jsdump
from texture2ddecoder import decode_astc as dastc, decode_etc2a8 as detc2a8

def rbin(fp:str, number:int = 0) -> bytes:
    """Reads binary data from a file

    Args:
        fp (str): The file path to read from
        number (int, optional): Number of bytes to read. If 0, reads the entire file. Default is 0
    """
    with open(fp, 'rb') as f:
        return f.read() if number == 0 else f.read(number)

def sbin(fp:str, data:bytes) -> None:
    """Writes binary data to a file

    Args:
        fp (str): The file path to write to
        data (bytes): The binary data to write
    """
    with open(fp, 'wb') as f:
        f.write(data)

def rjson(fp: str, encoding: str = 'utf-8') -> dict:
    """Reads JSON data from a file

    Args:
        fp (str): The file path to read from
        encoding (str, optional): The encoding used to read the file. Default is 'utf-8'
    """
    with open(fp, 'r', encoding=encoding) as f:
        return jsonload(f)

def sjson(fp: str, data: dict, encoding: str = 'utf-8'):
    """Writes JSON data to a file

    Args:
        fp (str): The file path to write to
        data (dict): The dictionary to write as JSON
        encoding (str, optional): The encoding used to write the file. Default is 'utf-8'
    """
    with open(fp, 'w', encoding=encoding) as f:
        jsdump(data, f, indent=4, ensure_ascii=False, separators=(',', ':'))

def rtext(fp: str, encoding: str = '') -> str:
    """Reads text data from a file, automatically decoding it using the provided encoding

    Args:
        fp (str): The file path to read from.
        encoding (str, optional): The text encoding to use. If empty, tries to auto-detect
    """
    return ctext(rbin(fp), encoding)

def stext(fp: str, data: str, encoding: str = 'utf-8') -> None:
    """Writes text data to a file

    Args:
        fp (str): The file path to write to
        data (str): The text data to write
        encoding (str, optional): The encoding to use when writing the file. Default is 'utf-8'
    """
    with open(fp, 'w', encoding=encoding) as f:
        f.write(data)

def rline(fp: str, encoding: str = '') -> list:
    """Reads a file line by line and returns a list of lines

    Args:
        fp (str): The file path to read from
        encoding (str, optional): The text encoding to use. If empty, tries to auto-detect
    """
    return cline(rbin(fp), encoding)

def sline(fp: str, data: list, encoding: str = 'utf-8') -> None:
    """Writes a list of strings to a file, each on a new line

    Args:
        fp (str): The file path to write to
        data (list): The list of strings to write
        encoding (str, optional): The encoding to use when writing the file. Default is 'utf-8'
    """
    with open(fp, 'w', encoding=encoding) as f:
        f.write('\n'.join(data))

def rzip(fp: Union[str, bytes], mode: str = 'r') -> ZipFile:
    """Reads or opens a ZIP file from a file path or byte data

    Args:
        fp (Union[str, bytes]): The file path or byte data to open as a ZIP file
        mode (str, optional): Mode in which to open the ZIP file. Default is 'r'
    """
    if isinstance(fp, bytes):
        fp = BytesIO(fp)
    return ZipFile(fp, mode)

# save img
def sbimg(fp: str, cimg: bytes, width: int, height: int, format: str) -> None:
    img = frombytes('RGBA', (width, height), cimg, 'raw', ('BGRA'))
    if format == 'JPEG':
        img = img.convert('RGB')
        img.save(fp, format='JPEG', quality=90)
    else:
        img.save(fp, format='PNG')

def gu16list(data: bytes, indices: list, byteorder: str, signed: bool = False) -> list:
    return [int.from_bytes(data[start:end], byteorder=byteorder, signed=signed) for start, end in indices]

def sastc(fp: str, data: bytes) -> None:
    """Saves an ASTC-compressed image to a file. If not ASTC, it writes the raw data

    Args:
        fp (str): The file path to save the image or raw data
        data (bytes): The raw data, expected to be ASTC-compressed
    """
    if data[:4] == b'\x13\xAB\xA1\x5C':
        aa, ab, ac, ad = gu16list(data, [(4, 5), (5, 6), (7, 9), (10, 12)], 'little')
        cimg = dastc(data[16:], ac, ad, aa, ab)
        sbimg(fp, cimg, ac, ad, 'JPEG' if fp.lower() == '.jpg' else 'PNG')
    else:
        sbin(fp, data)

def spkm(fp: str, data: bytes) -> None:
    """Saves a PKM-compressed image to a file. If not PKM, it writes the raw data

    Args:
        fp (str): The file path to save the image or raw data
        data (bytes): The raw data, expected to be PKM-compressed
    """
    if data[:3] == b'PKM':
        aa, ab, ac, ad = gu16list(data, [(8, 10), (10, 12), (12, 14), (14, 16)], 'big')
        cimg = detc2a8(data[16:], ac, ad)
        sbimg(fp, cimg, ac, ad, 'PNG')
    else:
        sbin(fp, data)

class KTX2PNG:
    HEADER = b'\xABKTX\x2011\xBB'
    HEADLEN = len(HEADER)
    ASTC = {b'\xB0\x93':(4, 4), b'\xB1\x93':(5, 4), b'\xB2\x93':(5, 5), b'\xB3\x93':(6, 5), b'\xB4\x93':(6, 6), b'\xB5\x93':(8, 5), b'\xB6\x93':(8, 6),
            b'\xB7\x93':(8, 8), b'\xB8\x93':(10, 5), b'\xB9\x93':(10, 6), b'\xBA\x93':(10, 8), b'\xBB\x93':(10, 10), b'\xBC\x93':(12, 10), b'\xBD\x93':(12, 12)}
    KTX11 = {k:[dastc, v[0], v[1]] for k, v in ASTC.items()}

    @classmethod
    def convert(cls, fp: str):
        try:
            with open(fp, 'rb') as file:
                img = cls.readimg(file, fp)
            if img in (0, 1):
                if img == 1: print('ERROR- ', fp)
                return None
            img.save(fp)
        except:
            print('ERROR- ', fp)

    @classmethod
    def readimg(cls, reader: BufferedReader, fp: str) -> Union[int, Image]:
        if reader.read(8) != cls.HEADER: return 0
        reader.seek(12)
        endian = '<' if reader.read(4) == b'\x01\x02\x03\x04' else '>'
        reader.seek(28)
        item = reader.read(2)
        if item not in cls.KTX11:
            print('ERROR- ', fp)
            return 1
        func, blockw, blockh = cls.KTX11[item]
        reader.seek(36)
        width, height = UnPack(f'{endian}2I', reader.read(8))
        reader.seek(60)
        cutlen = UnPack(f'{endian}I', reader.read(4))[0]
        reader.seek(64 + cutlen + 4)
        imgdata = func(reader.read(), width, height, blockw, blockh)
        img = frombytes('RGBA', (width, height), imgdata, 'raw', ('BGRA'))
        return img

# BinaryReader
class BinaryReader:
    """A class to read binary data from a stream with configurable endianness, signed/unsigned integers, and encoding

    Args
    ----
    stream : Union[BytesIO, BufferedReader, bytes, bytearray, str]
        - The input stream, which can be a byte stream, buffer, or string. If a string is provided, it will be decoded
    endian : bool, optional
        - If True, use little-endian byte order, otherwise use big-endian. Default is True (little-endian)
    signed : bool, optional
        - Whether integers should be interpreted as signed. Default is False
    encoding : str, optional
        - The text encoding used for decoding strings. Default is 'utf-8'

    Methods
    -------
    ```python
    read(length: int = -1) -> bytes
    ```
    >- Reads the specified number of bytes from the stream. If no length is provided, reads all remaining bytes
    
    ```python
        bint(length: int, signed: bool = None) -> int
    ```
    >- Reads an integer of specified byte length, interpreting it as signed or unsigned depending on the 'signed' parameter
        
    ```python
        str(length: int = -1, encoding: str = None) -> str
    ```
    >- Reads and decodes a string from the stream using the specified length and encoding

    ```python
        skip(length: int) -> None
    ```
    >- Skips the specified number of bytes in the stream
        
    ```python
        find(sign: bytes = b'\\x00') -> bytes
    ```
    >- Reads the stream until a specified byte sequence (sign) is found

    ```python
        PutUvarint(value: int) -> bytearray
    ```
    >- Encodes an integer as a varint and returns it as a bytearray
    
    Properties
    ----------
    **sign** : _bool_
    - Gets or sets whether integers are signed
        
    **endian** : _str_
    - Gets or sets the byte order ('<' for little-endian, '>' for big-endian)
        
    **encoding** : _str_
    - Gets or sets the string encoding for decoding

    **pos** : _int_
    - Gets or sets the current position in the stream
        
    **bool** : _bool_
    - Reads a single byte and interprets it as a boolean (True/False)
        
    **i8, i16, i32, i64** : _int_
    - Reads a signed 8-bit, 16-bit, 32-bit, or 64-bit integer from the stream
        
    **u8, u16, u32, u64** : _int_
    - Reads an unsigned 8-bit, 16-bit, 32-bit, or 64-bit integer from the stream
        
    **f32, f64** : _float_
    - Reads a 32-bit or 64-bit floating point number from the stream
        
    **len** : _int_
    - Returns the total length of the stream data
        
    **StrToNull** : _str_
    - Reads a string from the stream, stopping at the first null byte
        
    **ReadUvarint** : _int_
    - Reads an unsigned variable-length integer from the stream
    
    Examples
    --------
    ```python
    from Py3ComUtils.FileHandler import BinaryReader
    
    data:bytes
    reader = BinaryReader(data)
    uint32 = reader.u32
    int64 = reader.i64
    reader.pos = (0, -2) # Go to end of stream
    reader.skip(64) # Skip the current 64 bytes
    name = reader.str(5) # Read 5 bytes and decode as utf-8

    ```
    """
    reader: Union[BytesIO, BufferedReader]
    signed: bool
    sendian: str
    sendian2: str
    sencoding: str

    def __init__(self, stream:Union[BytesIO, BufferedReader, bytes, bytearray, str], endian:bool = True, signed:bool = False, encoding='utf-8'):
        """Initializes a BinaryReader object

        Args:
            stream (Union[BytesIO, BufferedReader, bytes, bytearray, str]): Input stream or data to be read
            endian (bool, optional): True for little-endian, False for big-endian. Default is True
            signed (bool, optional): Indicates if integers are signed. Default is False
            encoding (str, optional): Default encoding for reading strings. Default is 'utf-8'
        """
        if isinstance(stream, (bytes, bytearray, str)):
            if isinstance(stream, str): stream = rbin(stream)
            self.readerlen = len(stream)
            if stream.startswith(b'\x1F\x8B'): stream = dgzip(stream)
            self.reader = BytesIO(stream)
        elif isinstance(stream, BytesIO):
            self.readerlen = len(stream.getbuffer())
            self.reader = stream
        elif isinstance(stream, BufferedReader):
            stream.seek(0, 2)
            self.readerlen = stream.tell()
            self.reader = stream
            stream.seek(0)
        else:
            raise RuntimeError('Unsupported variable type')
        self.sendian = '<' if endian else '>'
        self.sendian2 = 'little' if endian else 'big'
        self.signed = signed
        self.sencoding = encoding

    def read(self, length:int = -1) -> bytes:
        """Reads a specified number of bytes from the stream

        Args:
            length (int, optional): Number of bytes to read. If -1, reads all bytes. Default is -1
        """
        return self.reader.read(length) if length != -1 else self.reader.read()

    def bint(self, length:int, signed: bool = None) -> int:
        """Reads an integer of specified length from the stream

        Args:
            length (int): The number of bytes to read
            signed (bool, optional): Specifies if the integer is signed. If None, uses the default. Default is None
        """
        if signed is None: signed = self.signed
        return int.from_bytes(self.read(length), byteorder=self.sendian2, signed=signed)

    def skip(self, length:int):
        """Skips a specified number of bytes in the stream

        Args:
            length (int): The number of bytes to skip
        """
        self.reader.seek(length, 1)

    def find(self, sign:bytes = b'\x00') -> bytes:
        """Reads bytes from the stream until a specified byte pattern is encountered

        Args:
            sign (bytes, optional): Byte pattern to stop at. Default is null byte (b'\\x00')
        """
        v = b''
        while True:
            b = self.reader.read(1)
            if b == sign: break
            v = b''.join((v, b))
        return v
    
    @staticmethod
    def PutUvarint(value:int) -> bytearray:
        """Encodes an integer into a Uvarint format

        Args:
            value (int): The integer to encode
        """
        result = bytearray()
        while value >= 0x80:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return result

    def IntArray(self, count: int, bit: int = 4) -> list[int]:
        return [self.bint(bit, True) for _ in range(count)]

    def UIntArray(self, count: int, bit: int = 4) -> list[int]:
        return [self.bint(bit, False) for _ in range(count)]

    def Int7bitArray(self, count: int) -> list[int]:
        return [self.ReadUvarint for _ in range(count)]

    def StrArray(self, count: int, bit: int = 4) -> list[str]:
        return [self.str(self.bint(bit, False)) for _ in range(count)]

    def StrArray7bit(self, count: int) -> list[str]:
        return [self.str(self.ReadUvarint) for _ in range(count)]

    def peek(self, number: int, mode: str = 'bytes') -> Union[bytes, int]:
        pos = self.pos
        if mode == 'bytes':
            result = self.read(number)
        elif mode == 'int':
            result = self.bint(number, True)
        elif mode == 'uint':
            result = self.bint(number, False)
        self.pos = pos
        return result

    @property
    def sign(self) -> str:
        """Gets or sets the signed attribute
        """
        return self.signed

    @sign.setter
    def sign(self, signed:bool):
        self.signed = signed

    @property
    def endian(self) -> str:
        """Gets or sets the endianness attribute
        """
        return self.sendian

    @endian.setter
    def endian(self, endian:bool):
        self.sendian = '<' if endian else '>'
        self.sendian2 = 'little' if endian else 'big'

    @property
    def encoding(self) -> str:
        """Gets or sets the encoding attribute
        """
        return self.sencoding

    @encoding.setter
    def encoding(self, encoding:str):
        self.sencoding = encoding

    @property
    def pos(self) -> int:
        """Gets or sets the current position in the stream
        """
        return self.reader.tell()

    @pos.setter
    def pos(self, value: Union[int, tuple]):
        if isinstance(value, tuple):
            pos, mode = (value[0], 0) if len(value) == 1 else value
        else:
            pos, mode = value, 0
        self.reader.seek(pos, mode)

    @property
    def bool(self) -> str:
        """Reads a single byte and returns it as a boolean
        """
        return bool(self.read(1)[0])

    @property
    def i8(self) -> int:
        """Reads a signed 8-bit integer
        """
        return self.bint(1, True)

    @property
    def i16(self) -> int:
        """Reads a signed 16-bit integer
        """
        return self.bint(2, True)

    @property
    def i24(self) -> int:
        """Reads a signed 24-bit integer
        """
        return self.bint(3, True)

    @property
    def i32(self) -> int:
        """Reads a signed 32-bit integer
        """
        return self.bint(4, True)

    @property
    def i64(self) -> int:
        """Reads a signed 64-bit integer
        """
        return self.bint(8, True)

    @property
    def u8(self) -> int:
        """Reads an unsigned 8-bit integer
        """
        return self.bint(1, False)

    @property
    def u16(self) -> int:
        """Reads an unsigned 16-bit integer
        """
        return self.bint(2, False)

    @property
    def u24(self) -> int:
        """Reads an unsigned 24-bit integer
        """
        return self.bint(3, False)

    @property
    def u32(self) -> int:
        """Reads an unsigned 32-bit integer
        """
        return self.bint(4, False)

    @property
    def u64(self) -> int:
        """Reads an unsigned 64-bit integer
        """
        return self.bint(8, False)

    @property
    def f32(self) -> int:
        """Reads a 32-bit floating-point number
        """
        return UnPack(f'{self.sendian}f', self.read(4))[0]

    @property
    def f64(self) -> int:
        """Reads a 64-bit floating-point number
        """
        return UnPack(f'{self.sendian}d', self.read(8))[0]

    @property
    def len(self) -> int:
        """Gets the total length of the stream
        """
        return self.readerlen

    @property
    def StrToNull(self) -> str:
        """Reads a string until a null byte is encountered
        """
        return self.find().decode(encoding=self.sencoding)

    @property
    def ReadUvarint(self) -> int:
        """Reads a Uvarint encoded integer from the stream
        """
        value, shift = 0, 0
        while True:
            byte = ord(self.reader.read(1))
            value |= (byte & 0x7F) << (shift % 64)
            shift += 7
            if byte & 0x80 == 0:
                break
        return value
    
    @staticmethod
    def ReadUvarintBytes(data: bytes, start: int = 0) -> int:
        value, shift, pos = 0, 0, start
        while True:
            byte = ord(data[pos:pos+1])
            value |= (byte & 0x7F) << (shift % 64)
            shift += 7
            if byte & 0x80 == 0:
                break
            pos += 1
        return value

    def str(self, length:int = -1, encoding:str = None) -> str:
        """Reads a string of specified length from the stream

        Args:
            length (int, optional): Number of bytes to read. If -1, reads based on a preceding length byte. Default is -1
            encoding (str, optional): The encoding to use. If None, uses the default encoding. Default is None
        """
        if encoding is None: encoding = self.sencoding
        return self.read(length).decode(encoding=encoding) if length != -1 else self.read(self.bint(1)).decode(encoding=encoding)
