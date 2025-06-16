
import sys
import struct


MAX_UINT32 = 0xffffffff
MAX_UINT24 = 0xffffff

DEFAULT_TIMEOUT = 3
START_FLASH_TIMEOUT = 20
CHIP_ERASE_TIMEOUT = 120
MAX_TIMEOUT = CHIP_ERASE_TIMEOUT * 2
SYNC_TIMEOUT = 0.1
MD5_TIMEOUT_PER_MB = 8
ERASE_REGION_TIMEOUT_PER_MB = 30


DETECTED_FLASH_SIZES = {0x12: '256KB', 0x13: '512KB', 0x14: '1MB',
                        0x15: '2MB', 0x16: '4MB', 0x17: '8MB', 0x18: '16MB'}

PYTHON2 = sys.version_info[0] < 3
if PYTHON2:
    def byte(bitstr, index):
        return ord(bitstr[index])
else:
    def byte(bitstr, index):
        return bitstr[index]
try:
    basestring
except NameError:
    basestring = str

def hexify(s):
    if not PYTHON2:
        return ''.join('%02X' % c for c in s)
    else:
        return ''.join('%02X' % ord(c) for c in s)

class FatalError(RuntimeError):
    def __init__(self, message):
        RuntimeError.__init__(self, message)

    @staticmethod
    def WithResult(message, result):
        message += " (result was %s)" % hexify(result)
        return FatalError(message)

class NotImplementedInROMError(FatalError):
    def __init__(self, bootloader, func):
        FatalError.__init__(self, "%s ROM does not support function %s." % (bootloader.CHIP_NAME, func.__name__))

def timeout_per_mb(seconds_per_mb, size_bytes):
    result = seconds_per_mb * (size_bytes / 1e6)
    if result < DEFAULT_TIMEOUT:
        return DEFAULT_TIMEOUT
    return result


def check_supported_function(func, check_func):
    
    def inner(*args, **kwargs):
        obj = args[0]
        if check_func(obj):
            return func(*args, **kwargs)
        else:
            raise NotImplementedInROMError(obj, func)
    return inner


def stub_function_only(func):
    return check_supported_function(func, lambda o: o.IS_STUB)

def stub_and_esp32_function_only(func):
    return check_supported_function(func, lambda o: o.IS_STUB or o.CHIP_NAME == "ESP32")

def div_roundup(a, b):
    return (int(a) + int(b) - 1) // int(b)
from .helpers import (
    arg_auto_int,
    align_file_position,
    flash_size_bytes,
    unhexify,
    pad_to
)

from .mem import (
    LoadFirmwareImage,
    load_ram,
    read_mem,
    write_mem,
    dump_mem,
    detect_flash_size
)
from .slip_reader import slip_reader
__all__ = [
    'arg_auto_int',
    'div_roundup',
    'align_file_position',
    'flash_size_bytes',
    'hexify',
    'unhexify',
    'pad_to',
    'FatalError',
    'NotImplementedInROMError',
    "timeout_per_mb",
    'check_supported_function',
    'stub_function_only',
    'stub_and_esp32_function_only',
    'check_supported_function',
    'PYTHON2',
    'basestring',
    'byte',
    'MAX_UINT32',
    'MAX_UINT24',
    'DEFAULT_TIMEOUT',
    'START_FLASH_TIMEOUT',
    'CHIP_ERASE_TIMEOUT',
    'MAX_TIMEOUT',
    'SYNC_TIMEOUT',
    'ERASE_REGION_TIMEOUT_PER_MB',
    'MD5_TIMEOUT_PER_MB',
    'DETECTED_FLASH_SIZES',
    'slip_reader',
    'LoadFirmwareImage',
    'load_ram',
    'read_mem',
    'write_mem',
    'dump_mem',
    'detect_flash_size'
]