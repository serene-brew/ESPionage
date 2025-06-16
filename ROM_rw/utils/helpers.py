import sys
from . import FatalError

PYTHON2 = sys.version_info[0] < 3

if PYTHON2:
    def byte(bitstr, index):
        return ord(bitstr[index])
else:
    def byte(bitstr, index):
        return bitstr[index]

def arg_auto_int(x):
    return int(x, 0)

def align_file_position(f, size):
    align = (size - 1) - (f.tell() % size)
    f.seek(align, 1)


def flash_size_bytes(size):
    if "MB" in size:
        return int(size[:size.index("MB")]) * 1024 * 1024
    elif "KB" in size:
        return int(size[:size.index("KB")]) * 1024
    else:
        raise FatalError("Unknown size %s" % size)

def unhexify(hs):
    s = bytes()

    for i in range(0, len(hs) - 1, 2):
        hex_string = hs[i:i + 2]

        if not PYTHON2:
            s += bytes([int(hex_string, 16)])
        else:
            s += chr(int(hex_string, 16))

    return s


def pad_to(data, alignment, pad_character=b'\xFF'):
    pad_mod = len(data) % alignment
    if pad_mod != 0:
        data += pad_character * (alignment - pad_mod)
    return data