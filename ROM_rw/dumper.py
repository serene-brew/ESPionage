from __future__ import division, print_function

import argparse
import base64
import copy
import hashlib
import inspect
import io
import os
import shlex
import struct
import sys
import time
import zlib

import serial

MAX_UINT32 = 0xffffffff
MAX_UINT24 = 0xffffff

DEFAULT_TIMEOUT = 3
START_FLASH_TIMEOUT = 20
CHIP_ERASE_TIMEOUT = 120
MAX_TIMEOUT = CHIP_ERASE_TIMEOUT * 2
SYNC_TIMEOUT = 0.1
MD5_TIMEOUT_PER_MB = 8
ERASE_REGION_TIMEOUT_PER_MB = 30


def timeout_per_mb(seconds_per_mb, size_bytes):
    result = seconds_per_mb * (size_bytes / 1e6)
    if result < DEFAULT_TIMEOUT:
        return DEFAULT_TIMEOUT
    return result


DETECTED_FLASH_SIZES = {0x12: '256KB', 0x13: '512KB', 0x14: '1MB',
                        0x15: '2MB', 0x16: '4MB', 0x17: '8MB', 0x18: '16MB'}


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


def esp8266_function_only(func):
    return check_supported_function(func, lambda o: o.CHIP_NAME == "ESP8266")


class ESPLoader(object):
    CHIP_NAME = "Espressif device"
    IS_STUB = False

    DEFAULT_PORT = "/dev/ttyUSB0"

    ESP_FLASH_BEGIN = 0x02
    ESP_FLASH_DATA  = 0x03
    ESP_FLASH_END   = 0x04
    ESP_MEM_BEGIN   = 0x05
    ESP_MEM_END     = 0x06
    ESP_MEM_DATA    = 0x07
    ESP_SYNC        = 0x08
    ESP_WRITE_REG   = 0x09
    ESP_READ_REG    = 0x0a

    ESP_SPI_SET_PARAMS = 0x0B
    ESP_SPI_ATTACH     = 0x0D
    ESP_CHANGE_BAUDRATE = 0x0F
    ESP_FLASH_DEFL_BEGIN = 0x10
    ESP_FLASH_DEFL_DATA  = 0x11
    ESP_FLASH_DEFL_END   = 0x12
    ESP_SPI_FLASH_MD5    = 0x13

    ESP_ERASE_FLASH = 0xD0
    ESP_ERASE_REGION = 0xD1
    ESP_READ_FLASH = 0xD2
    ESP_RUN_USER_CODE = 0xD3

    ESP_RAM_BLOCK   = 0x1800

    FLASH_WRITE_SIZE = 0x400

    ESP_ROM_BAUD    = 115200

    ESP_IMAGE_MAGIC = 0xe9

    ESP_CHECKSUM_MAGIC = 0xef

    FLASH_SECTOR_SIZE = 0x1000

    UART_DATA_REG_ADDR = 0x60000078

    IROM_MAP_START = 0x40200000
    IROM_MAP_END = 0x40300000

    STATUS_BYTES_LENGTH = 2

    def __init__(self, port=DEFAULT_PORT, baud=ESP_ROM_BAUD, trace_enabled=False):
        if isinstance(port, basestring):
            self._port = serial.serial_for_url(port)
        else:
            self._port = port
        self._slip_reader = slip_reader(self._port, self.trace)
        self._set_port_baudrate(baud)
        self._trace_enabled = trace_enabled

    def _set_port_baudrate(self, baud):
        try:
            self._port.baudrate = baud
        except IOError:
            raise FatalError("Failed to set baud rate %d. The driver may not support this rate." % baud)

    @staticmethod
    def detect_chip(port=DEFAULT_PORT, baud=ESP_ROM_BAUD, connect_mode='default_reset', trace_enabled=False):
        detect_port = ESPLoader(port, baud, trace_enabled=trace_enabled)
        detect_port.connect(connect_mode)
        print('Detecting chip type...', end='')
        sys.stdout.flush()
        date_reg = detect_port.read_reg(ESPLoader.UART_DATA_REG_ADDR)

        for cls in [ESP8266ROM, ESP32ROM]:
            if date_reg == cls.DATE_REG_VALUE:
                # don't connect a second time
                inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                print(' %s' % inst.CHIP_NAME)
                return inst
        print('')
        raise FatalError("Unexpected UART datecode value 0x%08x. Failed to autodetect chip type." % date_reg)

    def read(self):
        return next(self._slip_reader)

    def write(self, packet):
        buf = b'\xc0' \
              + (packet.replace(b'\xdb',b'\xdb\xdd').replace(b'\xc0',b'\xdb\xdc')) \
              + b'\xc0'
        self.trace("Write %d bytes: %r", len(buf), buf)
        self._port.write(buf)

    def trace(self, message, *format_args):
        if self._trace_enabled:
            now = time.time()
            try:

                delta = now - self._last_trace
            except AttributeError:
                delta = 0.0
            self._last_trace = now
            prefix = "TRACE +%.3f " % delta
            print(prefix + (message % format_args))

    @staticmethod
    def checksum(data, state=ESP_CHECKSUM_MAGIC):
        for b in data:
            if type(b) is int:
                state ^= b
            else:
                state ^= ord(b)

        return state

    def command(self, op=None, data=b"", chk=0, wait_response=True, timeout=DEFAULT_TIMEOUT):
        saved_timeout = self._port.timeout
        new_timeout = min(timeout, MAX_TIMEOUT)
        if new_timeout != saved_timeout:
            self._port.timeout = new_timeout

        try:
            if op is not None:
                self.trace("command op=0x%02x data len=%s wait_response=%d timeout=%.3f data=%r",
                           op, len(data), 1 if wait_response else 0, timeout, data)
                pkt = struct.pack(b'<BBHI', 0x00, op, len(data), chk) + data
                self.write(pkt)

            if not wait_response:
                return

            for retry in range(100):
                p = self.read()
                if len(p) < 8:
                    continue
                (resp, op_ret, len_ret, val) = struct.unpack('<BBHI', p[:8])
                if resp != 1:
                    continue
                data = p[8:]
                if op is None or op_ret == op:
                    return val, data
        finally:
            if new_timeout != saved_timeout:
                self._port.timeout = saved_timeout

        raise FatalError("Response doesn't match request")

    def check_command(self, op_description, op=None, data=b'', chk=0, timeout=DEFAULT_TIMEOUT):
        val, data = self.command(op, data, chk, timeout=timeout)

        if len(data) < self.STATUS_BYTES_LENGTH:
            raise FatalError("Failed to %s. Only got %d byte status response." % (op_description, len(data)))
        status_bytes = data[-self.STATUS_BYTES_LENGTH:]

        if byte(status_bytes, 0) != 0:
            raise FatalError.WithResult('Failed to %s' % op_description, status_bytes)

        if len(data) > self.STATUS_BYTES_LENGTH:
            return data[:-self.STATUS_BYTES_LENGTH]
        else:
            return val

    def flush_input(self):
        self._port.flushInput()
        self._slip_reader = slip_reader(self._port, self.trace)

    def sync(self):
        self.command(self.ESP_SYNC, b'\x07\x07\x12\x20' + 32 * b'\x55',
                     timeout=SYNC_TIMEOUT)
        for i in range(7):
            self.command()

    def _connect_attempt(self, mode='default_reset', esp32r0_delay=False):
        
        last_error = None

        if mode != 'no_reset':
            self._port.setDTR(False)
            self._port.setRTS(True)
            time.sleep(0.1)
            if esp32r0_delay:
            
                time.sleep(1.2)
            self._port.setDTR(True)
            self._port.setRTS(False)
            if esp32r0_delay:
                time.sleep(0.4)
            time.sleep(0.05)
            self._port.setDTR(False)

        for _ in range(5):
            try:
                self.flush_input()
                self._port.flushOutput()
                self.sync()
                return None
            except FatalError as e:
                if esp32r0_delay:
                    print('_', end='')
                else:
                    print('.', end='')
                sys.stdout.flush()
                time.sleep(0.05)
                last_error = e
        return last_error

    def connect(self, mode='default_reset'):
        print('Connecting...', end='')
        sys.stdout.flush()
        last_error = None

        try:
            for _ in range(10):
                last_error = self._connect_attempt(mode=mode, esp32r0_delay=False)
                if last_error is None:
                    return
                last_error = self._connect_attempt(mode=mode, esp32r0_delay=True)
                if last_error is None:
                    return
        finally:
            print('')
        raise FatalError('Failed to connect to %s: %s' % (self.CHIP_NAME, last_error))

    def read_reg(self, addr):
        val, data = self.command(self.ESP_READ_REG, struct.pack('<I', addr))
        if byte(data, 0) != 0:
            raise FatalError.WithResult("Failed to read register address %08x" % addr, data)
        return val

    def write_reg(self, addr, value, mask=0xFFFFFFFF, delay_us=0):
        return self.check_command("write target memory", self.ESP_WRITE_REG,
                                  struct.pack('<IIII', addr, value, mask, delay_us))

    def mem_begin(self, size, blocks, blocksize, offset):
        return self.check_command("enter RAM download mode", self.ESP_MEM_BEGIN,
                                  struct.pack('<IIII', size, blocks, blocksize, offset))

    def mem_block(self, data, seq):
        return self.check_command("write to target RAM", self.ESP_MEM_DATA,
                                  struct.pack('<IIII', len(data), seq, 0, 0) + data,
                                  self.checksum(data))

    def mem_finish(self, entrypoint=0):
        return self.check_command("leave RAM download mode", self.ESP_MEM_END,
                                  struct.pack('<II', int(entrypoint == 0), entrypoint))


    def flash_begin(self, size, offset):
        num_blocks = (size + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE
        erase_size = self.get_erase_size(offset, size)

        t = time.time()
        if self.IS_STUB:
            timeout = DEFAULT_TIMEOUT
        else:
            timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, size)
        self.check_command("enter Flash download mode", self.ESP_FLASH_BEGIN,
                           struct.pack('<IIII', erase_size, num_blocks, self.FLASH_WRITE_SIZE, offset),
                           timeout=timeout)
        if size != 0 and not self.IS_STUB:
            print("Took %.2fs to erase flash block" % (time.time() - t))
        return num_blocks

    def flash_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        self.check_command("write to target Flash after seq %d" % seq,
                           self.ESP_FLASH_DATA,
                           struct.pack('<IIII', len(data), seq, 0, 0) + data,
                           self.checksum(data),
                           timeout=timeout)

    def flash_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        self.check_command("leave Flash mode", self.ESP_FLASH_END, pkt)

    def run(self, reboot=False):
        self.flash_begin(0, 0)
        self.flash_finish(reboot)

    def flash_id(self):
        SPIFLASH_RDID = 0x9F
        return self.run_spiflash_command(SPIFLASH_RDID, b"", 24)

    def parse_flash_size_arg(self, arg):
        try:
            return self.FLASH_SIZES[arg]
        except KeyError:
            raise FatalError("Flash size '%s' is not supported by this chip type. Supported sizes: %s"
                             % (arg, ", ".join(self.FLASH_SIZES.keys())))

    def run_stub(self, stub=None):
        if stub is None:
            if self.IS_STUB:
                raise FatalError("Not possible for a stub to load another stub (memory likely to overlap.)")
            stub = self.STUB_CODE

        print("Uploading stub...")
        for field in ['text', 'data']:
            if field in stub:
                offs = stub[field + "_start"]
                length = len(stub[field])
                blocks = (length + self.ESP_RAM_BLOCK - 1) // self.ESP_RAM_BLOCK
                self.mem_begin(length, blocks, self.ESP_RAM_BLOCK, offs)
                for seq in range(blocks):
                    from_offs = seq * self.ESP_RAM_BLOCK
                    to_offs = from_offs + self.ESP_RAM_BLOCK
                    self.mem_block(stub[field][from_offs:to_offs], seq)
        print("Running stub...")
        self.mem_finish(stub['entry'])

        p = self.read()
        if p != b'OHAI':
            raise FatalError("Failed to start stub. Unexpected response: %s" % p)
        print("Stub running...")
        return self.STUB_CLASS(self)

    @stub_and_esp32_function_only
    def flash_defl_begin(self, size, compsize, offset):
        num_blocks = (compsize + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE
        erase_blocks = (size + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE

        t = time.time()
        if self.IS_STUB:
            write_size = size
            timeout = DEFAULT_TIMEOUT
        else:
            write_size = erase_blocks * self.FLASH_WRITE_SIZE
            timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, write_size)
        print("Compressed %d bytes to %d..." % (size, compsize))
        self.check_command("enter compressed flash mode", self.ESP_FLASH_DEFL_BEGIN,
                           struct.pack('<IIII', write_size, num_blocks, self.FLASH_WRITE_SIZE, offset),
                           timeout=timeout)
        if size != 0 and not self.IS_STUB:
            print("Took %.2fs to erase flash block" % (time.time() - t))
        return num_blocks

    @stub_and_esp32_function_only
    def flash_defl_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        self.check_command("write compressed data to flash after seq %d" % seq,
                           self.ESP_FLASH_DEFL_DATA, struct.pack('<IIII', len(data), seq, 0, 0) + data, self.checksum(data), timeout=timeout)

    @stub_and_esp32_function_only
    def flash_defl_finish(self, reboot=False):
        if not reboot and not self.IS_STUB:
            return
        pkt = struct.pack('<I', int(not reboot))
        self.check_command("leave compressed flash mode", self.ESP_FLASH_DEFL_END, pkt)
        self.in_bootloader = False

    @stub_and_esp32_function_only
    def flash_md5sum(self, addr, size):
        timeout = timeout_per_mb(MD5_TIMEOUT_PER_MB, size)
        res = self.check_command('calculate md5sum', self.ESP_SPI_FLASH_MD5, struct.pack('<IIII', addr, size, 0, 0),
                                 timeout=timeout)

        if len(res) == 32:
            return res.decode("utf-8")
        elif len(res) == 16:
            return hexify(res).lower()
        else:
            raise FatalError("MD5Sum command returned unexpected result: %r" % res)

    @stub_and_esp32_function_only
    def change_baud(self, baud):
        print("Changing baud rate to %d" % baud)
        second_arg = self._port.baudrate if self.IS_STUB else 0
        self.command(self.ESP_CHANGE_BAUDRATE, struct.pack('<II', baud, second_arg))
        print("Changed.")
        self._set_port_baudrate(baud)
        time.sleep(0.05)
        self.flush_input()

    @stub_function_only
    def erase_flash(self):

        self.check_command("erase flash", self.ESP_ERASE_FLASH,
                           timeout=CHIP_ERASE_TIMEOUT)

    @stub_function_only
    def erase_region(self, offset, size):
        if offset % self.FLASH_SECTOR_SIZE != 0:
            raise FatalError("Offset to erase from must be a multiple of 4096")
        if size % self.FLASH_SECTOR_SIZE != 0:
            raise FatalError("Size of data to erase must be a multiple of 4096")
        timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, size)
        self.check_command("erase region", self.ESP_ERASE_REGION, struct.pack('<II', offset, size), timeout=timeout)

    @stub_function_only
    def read_flash(self, offset, length, progress_fn=None):
        self.check_command("read flash", self.ESP_READ_FLASH,
                           struct.pack('<IIII',
                                       offset,
                                       length,
                                       self.FLASH_SECTOR_SIZE,
                                       64))
        data = b''
        while len(data) < length:
            p = self.read()
            data += p
            self.write(struct.pack('<I', len(data)))
            if progress_fn and (len(data) % 1024 == 0 or len(data) == length):
                progress_fn(len(data), length)
        if progress_fn:
            progress_fn(len(data), length)
        if len(data) > length:
            raise FatalError('Read more than expected')
        digest_frame = self.read()
        if len(digest_frame) != 16:
            raise FatalError('Expected digest, got: %s' % hexify(digest_frame))
        expected_digest = hexify(digest_frame).upper()
        digest = hashlib.md5(data).hexdigest().upper()
        if digest != expected_digest:
            raise FatalError('Digest mismatch: expected %s, got %s' % (expected_digest, digest))
        return data

    def flash_spi_attach(self, hspi_arg):
        arg = struct.pack('<I', hspi_arg)
        if not self.IS_STUB:
            is_legacy = 0
            arg += struct.pack('BBBB', is_legacy, 0, 0, 0)
        self.check_command("configure SPI flash pins", ESP32ROM.ESP_SPI_ATTACH, arg)

    def flash_set_parameters(self, size):
        fl_id = 0
        total_size = size
        block_size = 64 * 1024
        sector_size = 4 * 1024
        page_size = 256
        status_mask = 0xffff
        self.check_command("set SPI params", ESP32ROM.ESP_SPI_SET_PARAMS,
                           struct.pack('<IIIIII', fl_id, total_size, block_size, sector_size, page_size, status_mask))

    def run_spiflash_command(self, spiflash_command, data=b"", read_bits=0):
        SPI_USR_COMMAND = (1 << 31)
        SPI_USR_MISO    = (1 << 28)
        SPI_USR_MOSI    = (1 << 27)

        base = self.SPI_REG_BASE
        SPI_CMD_REG       = base + 0x00
        SPI_USR_REG       = base + 0x1C
        SPI_USR1_REG      = base + 0x20
        SPI_USR2_REG      = base + 0x24
        SPI_W0_REG        = base + self.SPI_W0_OFFS

        if self.SPI_HAS_MOSI_DLEN_REG:
            def set_data_lengths(mosi_bits, miso_bits):
                SPI_MOSI_DLEN_REG = base + 0x28
                SPI_MISO_DLEN_REG = base + 0x2C
                if mosi_bits > 0:
                    self.write_reg(SPI_MOSI_DLEN_REG, mosi_bits - 1)
                if miso_bits > 0:
                    self.write_reg(SPI_MISO_DLEN_REG, miso_bits - 1)
        else:

            def set_data_lengths(mosi_bits, miso_bits):
                SPI_DATA_LEN_REG = SPI_USR1_REG
                SPI_MOSI_BITLEN_S = 17
                SPI_MISO_BITLEN_S = 8
                mosi_mask = 0 if (mosi_bits == 0) else (mosi_bits - 1)
                miso_mask = 0 if (miso_bits == 0) else (miso_bits - 1)
                self.write_reg(SPI_DATA_LEN_REG,
                               (miso_mask << SPI_MISO_BITLEN_S) | (
                                   mosi_mask << SPI_MOSI_BITLEN_S))

        SPI_CMD_USR  = (1 << 18)

        SPI_USR2_DLEN_SHIFT = 28

        if read_bits > 32:
            raise FatalError("Reading more than 32 bits back from a SPI flash operation is unsupported")
        if len(data) > 64:
            raise FatalError("Writing more than 64 bytes of data with one SPI command is unsupported")

        data_bits = len(data) * 8
        old_spi_usr = self.read_reg(SPI_USR_REG)
        old_spi_usr2 = self.read_reg(SPI_USR2_REG)
        flags = SPI_USR_COMMAND
        if read_bits > 0:
            flags |= SPI_USR_MISO
        if data_bits > 0:
            flags |= SPI_USR_MOSI
        set_data_lengths(data_bits, read_bits)
        self.write_reg(SPI_USR_REG, flags)
        self.write_reg(SPI_USR2_REG,
                       (7 << SPI_USR2_DLEN_SHIFT) | spiflash_command)
        if data_bits == 0:
            self.write_reg(SPI_W0_REG, 0)
        else:
            data = pad_to(data, 4, b'\00')
            words = struct.unpack("I" * (len(data) // 4), data)
            next_reg = SPI_W0_REG
            for word in words:
                self.write_reg(next_reg, word)
                next_reg += 4
        self.write_reg(SPI_CMD_REG, SPI_CMD_USR)

        def wait_done():
            for _ in range(10):
                if (self.read_reg(SPI_CMD_REG) & SPI_CMD_USR) == 0:
                    return
            raise FatalError("SPI command did not complete in time")
        wait_done()

        status = self.read_reg(SPI_W0_REG)
        self.write_reg(SPI_USR_REG, old_spi_usr)
        self.write_reg(SPI_USR2_REG, old_spi_usr2)
        return status

    def read_status(self, num_bytes=2):
        SPIFLASH_RDSR  = 0x05
        SPIFLASH_RDSR2 = 0x35
        SPIFLASH_RDSR3 = 0x15

        status = 0
        shift = 0
        for cmd in [SPIFLASH_RDSR, SPIFLASH_RDSR2, SPIFLASH_RDSR3][0:num_bytes]:
            status += self.run_spiflash_command(cmd, read_bits=8) << shift
            shift += 8
        return status

    def write_status(self, new_status, num_bytes=2, set_non_volatile=False):
        SPIFLASH_WRSR = 0x01
        SPIFLASH_WRSR2 = 0x31
        SPIFLASH_WRSR3 = 0x11
        SPIFLASH_WEVSR = 0x50
        SPIFLASH_WREN = 0x06
        SPIFLASH_WRDI = 0x04

        enable_cmd = SPIFLASH_WREN if set_non_volatile else SPIFLASH_WEVSR
        if num_bytes == 2:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(SPIFLASH_WRSR, struct.pack("<H", new_status))

        for cmd in [SPIFLASH_WRSR, SPIFLASH_WRSR2, SPIFLASH_WRSR3][0:num_bytes]:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(cmd, struct.pack("B", new_status & 0xFF))
            new_status >>= 8

        self.run_spiflash_command(SPIFLASH_WRDI)

    def hard_reset(self):
        self._port.setRTS(True)
        time.sleep(0.1)
        self._port.setRTS(False)

    def soft_reset(self, stay_in_bootloader):
        if not self.IS_STUB:
            if stay_in_bootloader:
                return
            else:
                self.flash_begin(0, 0)
                self.flash_finish(False)
        else:
            if stay_in_bootloader:
                self.flash_begin(0, 0)
                self.flash_finish(True)
            elif self.CHIP_NAME != "ESP8266":
                raise FatalError("Soft resetting is currently only supported on ESP8266")
            else:
                self.command(self.ESP_RUN_USER_CODE, wait_response=False)


class ESP8266ROM(ESPLoader):
    CHIP_NAME = "ESP8266"
    IS_STUB = False

    DATE_REG_VALUE = 0x00062000

    ESP_OTP_MAC0    = 0x3ff00050
    ESP_OTP_MAC1    = 0x3ff00054
    ESP_OTP_MAC3    = 0x3ff0005c

    SPI_REG_BASE    = 0x60000200
    SPI_W0_OFFS     = 0x40
    SPI_HAS_MOSI_DLEN_REG = False

    FLASH_SIZES = {
        '512KB':0x00,
        '256KB':0x10,
        '1MB':0x20,
        '2MB':0x30,
        '4MB':0x40,
        '2MB-c1': 0x50,
        '4MB-c1':0x60,
        '8MB':0x80,
        '16MB':0x90,
    }

    BOOTLOADER_FLASH_OFFSET = 0

    def get_efuses(self):
        return (self.read_reg(0x3ff0005c) << 96 |
                self.read_reg(0x3ff00058) << 64 |
                self.read_reg(0x3ff00054) << 32 |
                self.read_reg(0x3ff00050))

    def get_chip_description(self):
        efuses = self.get_efuses()
        is_8285 = (efuses & ((1 << 4) | 1 << 80)) != 0
        return "ESP8285" if is_8285 else "ESP8266EX"

    def get_chip_features(self):
        features = ["WiFi"]
        if self.get_chip_description() == "ESP8285":
            features += ["Embedded Flash"]
        return features

    def flash_spi_attach(self, hspi_arg):
        if self.IS_STUB:
            super(ESP8266ROM, self).flash_spi_attach(hspi_arg)
        else:

            self.flash_begin(0, 0)

    def flash_set_parameters(self, size):

        if self.IS_STUB:
            super(ESP8266ROM, self).flash_set_parameters(size)

    def chip_id(self):
        id0 = self.read_reg(self.ESP_OTP_MAC0)
        id1 = self.read_reg(self.ESP_OTP_MAC1)
        return (id0 >> 24) | ((id1 & MAX_UINT24) << 8)

    def read_mac(self):

        mac0 = self.read_reg(self.ESP_OTP_MAC0)
        mac1 = self.read_reg(self.ESP_OTP_MAC1)
        mac3 = self.read_reg(self.ESP_OTP_MAC3)
        if (mac3 != 0):
            oui = ((mac3 >> 16) & 0xff, (mac3 >> 8) & 0xff, mac3 & 0xff)
        elif ((mac1 >> 16) & 0xff) == 0:
            oui = (0x18, 0xfe, 0x34)
        elif ((mac1 >> 16) & 0xff) == 1:
            oui = (0xac, 0xd0, 0x74)
        else:
            raise FatalError("Unknown OUI")
        return oui + ((mac1 >> 8) & 0xff, mac1 & 0xff, (mac0 >> 24) & 0xff)

    def get_erase_size(self, offset, size):
        sectors_per_block = 16
        sector_size = self.FLASH_SECTOR_SIZE
        num_sectors = (size + sector_size - 1) // sector_size
        start_sector = offset // sector_size

        head_sectors = sectors_per_block - (start_sector % sectors_per_block)
        if num_sectors < head_sectors:
            head_sectors = num_sectors

        if num_sectors < 2 * head_sectors:
            return (num_sectors + 1) // 2 * sector_size
        else:
            return (num_sectors - head_sectors) * sector_size


class ESP8266StubLoader(ESP8266ROM):
    FLASH_WRITE_SIZE = 0x4000
    IS_STUB = True

    def __init__(self, rom_loader):
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()

    def get_erase_size(self, offset, size):
        return size


ESP8266ROM.STUB_CLASS = ESP8266StubLoader


class ESP32ROM(ESPLoader):
    CHIP_NAME = "ESP32"
    IS_STUB = False

    DATE_REG_VALUE = 0x15122500

    IROM_MAP_START = 0x400d0000
    IROM_MAP_END   = 0x40400000
    DROM_MAP_START = 0x3F400000
    DROM_MAP_END   = 0x3F800000

    STATUS_BYTES_LENGTH = 4

    SPI_REG_BASE   = 0x60002000
    EFUSE_REG_BASE = 0x6001a000

    SPI_W0_OFFS = 0x80
    SPI_HAS_MOSI_DLEN_REG = True

    FLASH_SIZES = {
        '1MB':0x00,
        '2MB':0x10,
        '4MB':0x20,
        '8MB':0x30,
        '16MB':0x40
    }

    BOOTLOADER_FLASH_OFFSET = 0x1000

    def get_chip_description(self):
        word3 = self.read_efuse(3)
        chip_version = (word3 >> 12) & 0xF
        pkg_version = (word3 >> 9) & 0x07

        silicon_rev = {
            0x0: "0",
            0x8: "1",
            0xc: "1",
        }.get(chip_version, "(unknown 0x%x)" % chip_version)

        chip_name = {
            0: "ESP32D0WDQ6",
            1: "ESP32D0WDQ5",
            2: "ESP32D2WDQ5",
            5: "ESP32-PICO-D4",
        }.get(pkg_version, "unknown ESP32")

        return "%s (revision %s)" % (chip_name, silicon_rev)

    def get_chip_features(self):
        features = ["WiFi"]
        word3 = self.read_efuse(3)

        if word3 & (1 << 1) == 0:
            features += ["BT"]

        if word3 & (1 << 0):
            features += ["Single Core"]
        else:
            features += ["Dual Core"]

        pkg_version = (word3 >> 9) & 0x07
        if pkg_version != 0:
            features += ["Embedded Flash"]

        word4 = self.read_efuse(4)
        vref = (word4 >> 8) & 0x1F
        if vref != 0:
            features += ["VRef calibration in efuse"]

        return features

    def read_efuse(self, n):
        return self.read_reg(self.EFUSE_REG_BASE + (4 * n))

    def chip_id(self):
        word16 = self.read_efuse(1)
        word17 = self.read_efuse(2)
        return ((word17 & MAX_UINT24) << 24) | (word16 >> 8) & MAX_UINT24

    def read_mac(self):
        words = [self.read_efuse(2), self.read_efuse(1)]
        bitstring = struct.pack(">II", *words)
        bitstring = bitstring[2:8]
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:
            return tuple(bitstring)

    def get_erase_size(self, offset, size):
        return size


class ESP32StubLoader(ESP32ROM):
    FLASH_WRITE_SIZE = 0x4000  
    STATUS_BYTES_LENGTH = 2
    IS_STUB = True

    def __init__(self, rom_loader):
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()

ESP32ROM.STUB_CLASS = ESP32StubLoader

class ESPBOOTLOADER(object):
    IMAGE_V2_MAGIC = 0xea

    IMAGE_V2_SEGMENT = 4


def LoadFirmwareImage(chip, filename):
    with open(filename, 'rb') as f:
        if chip == 'esp32':
            return ESP32FirmwareImage(f)
        else:
            magic = ord(f.read(1))
            f.seek(0)
            if magic == ESPLoader.ESP_IMAGE_MAGIC:
                return ESPFirmwareImage(f)
            elif magic == ESPBOOTLOADER.IMAGE_V2_MAGIC:
                return OTAFirmwareImage(f)
            else:
                raise FatalError("Invalid image magic number: %d" % magic)


class ImageSegment(object):
    def __init__(self, addr, data, file_offs=None):
        self.addr = addr

        self.data = pad_to(data, 4, b'\x00')
        self.file_offs = file_offs
        self.include_in_checksum = True

    def copy_with_new_addr(self, new_addr):
        return ImageSegment(new_addr, self.data, 0)

    def split_image(self, split_len):
        result = copy.copy(self)
        result.data = self.data[:split_len]
        self.data = self.data[split_len:]
        self.addr += split_len
        self.file_offs = None
        result.file_offs = None
        return result

    def __repr__(self):
        r = "len 0x%05x load 0x%08x" % (len(self.data), self.addr)
        if self.file_offs is not None:
            r += " file_offs 0x%08x" % (self.file_offs)
        return r


class ELFSection(ImageSegment):
    def __init__(self, name, addr, data):
        super(ELFSection, self).__init__(addr, data)
        self.name = name.decode("utf-8")

    def __repr__(self):
        return "%s %s" % (self.name, super(ELFSection, self).__repr__())


class BaseFirmwareImage(object):
    SEG_HEADER_LEN = 8
    def __init__(self):
        self.segments = []
        self.entrypoint = 0

    def load_common_header(self, load_file, expected_magic):
            (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', load_file.read(8))

            if magic != expected_magic or segments > 16:
                raise FatalError('Invalid firmware image magic=%d segments=%d' % (magic, segments))
            return segments

    def load_segment(self, f, is_irom_segment=False):
        file_offs = f.tell()
        (offset, size) = struct.unpack('<II', f.read(8))
        self.warn_if_unusual_segment(offset, size, is_irom_segment)
        segment_data = f.read(size)
        if len(segment_data) < size:
            raise FatalError('End of file reading segment 0x%x, length %d (actual length %d)' % (offset, size, len(segment_data)))
        segment = ImageSegment(offset, segment_data, file_offs)
        self.segments.append(segment)
        return segment

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        if not is_irom_segment:
            if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                print('WARNING: Suspicious segment 0x%x, length %d' % (offset, size))

    def save_segment(self, f, segment, checksum=None):
        f.write(struct.pack('<II', segment.addr, len(segment.data)))
        f.write(segment.data)
        if checksum is not None:
            return ESPLoader.checksum(segment.data, checksum)

    def read_checksum(self, f):
        align_file_position(f, 16)
        return ord(f.read(1))

    def calculate_checksum(self):
        checksum = ESPLoader.ESP_CHECKSUM_MAGIC
        for seg in self.segments:
            if seg.include_in_checksum:
                checksum = ESPLoader.checksum(seg.data, checksum)
        return checksum

    def append_checksum(self, f, checksum):
        align_file_position(f, 16)
        f.write(struct.pack(b'B', checksum))

    def write_common_header(self, f, segments):
        f.write(struct.pack('<BBBBI', ESPLoader.ESP_IMAGE_MAGIC, len(segments),
                            self.flash_mode, self.flash_size_freq, self.entrypoint))

    def is_irom_addr(self, addr):
        return ESP8266ROM.IROM_MAP_START <= addr < ESP8266ROM.IROM_MAP_END

    def get_irom_segment(self):
            irom_segments = [s for s in self.segments if self.is_irom_addr(s.addr)]
            if len(irom_segments) > 0:
                if len(irom_segments) != 1:
                    raise FatalError('Found %d segments that could be irom0. Bad ELF file?' % len(irom_segments))
                return irom_segments[0]
            return None

    def get_non_irom_segments(self):
        irom_segment = self.get_irom_segment()
        return [s for s in self.segments if s != irom_segment]


class ESPFirmwareImage(BaseFirmwareImage):

    ROM_LOADER = ESP8266ROM

    def __init__(self, load_file=None):
        super(ESPFirmwareImage, self).__init__()
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1

        if load_file is not None:
            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

    def default_output_name(self, input_file):
        return input_file + '-'

    def save(self, basename):
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            with open("%s0x%05x.bin" % (basename, irom_segment.addr - ESP8266ROM.IROM_MAP_START), "wb") as f:
                f.write(irom_segment.data)

        normal_segments = self.get_non_irom_segments()
        with open("%s0x00000.bin" % basename, 'wb') as f:
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


class OTAFirmwareImage(BaseFirmwareImage):
    ROM_LOADER = ESP8266ROM

    def __init__(self, load_file=None):
        super(OTAFirmwareImage, self).__init__()
        self.version = 2
        if load_file is not None:
            segments = self.load_common_header(load_file, ESPBOOTLOADER.IMAGE_V2_MAGIC)
            if segments != ESPBOOTLOADER.IMAGE_V2_SEGMENT:
                print('Warning: V2 header has unexpected "segment" count %d (usually 4)' % segments)

            irom_segment = self.load_segment(load_file, True)
            irom_segment.addr = 0
            irom_segment.include_in_checksum = False

            first_flash_mode = self.flash_mode
            first_flash_size_freq = self.flash_size_freq
            first_entrypoint = self.entrypoint

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

            if first_flash_mode != self.flash_mode:
                print('WARNING: Flash mode value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_mode, self.flash_mode))
            if first_flash_size_freq != self.flash_size_freq:
                print('WARNING: Flash size/freq value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_size_freq, self.flash_size_freq))
            if first_entrypoint != self.entrypoint:
                print('WARNING: Entrypoint address in first header (0x%08x) disagrees with second header (0x%08x). Using second value.'
                      % (first_entrypoint, self.entrypoint))

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

    def default_output_name(self, input_file):
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            irom_offs = irom_segment.addr - ESP8266ROM.IROM_MAP_START
        else:
            irom_offs = 0
        return "%s-0x%05x.bin" % (os.path.splitext(input_file)[0],
                                  irom_offs & ~(ESPLoader.FLASH_SECTOR_SIZE - 1))

    def save(self, filename):
        with open(filename, 'wb') as f:
            f.write(struct.pack(b'<BBBBI', ESPBOOTLOADER.IMAGE_V2_MAGIC, ESPBOOTLOADER.IMAGE_V2_SEGMENT,
                                self.flash_mode, self.flash_size_freq, self.entrypoint))

            irom_segment = self.get_irom_segment()
            if irom_segment is not None:
                irom_segment = irom_segment.copy_with_new_addr(0)
                self.save_segment(f, irom_segment)

            normal_segments = self.get_non_irom_segments()
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


class ESP32FirmwareImage(BaseFirmwareImage):

    ROM_LOADER = ESP32ROM
    WP_PIN_DISABLED = 0xEE

    EXTENDED_HEADER_STRUCT_FMT = "B" * 16

    def __init__(self, load_file=None):
        super(ESP32FirmwareImage, self).__init__()
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1
        self.wp_pin = self.WP_PIN_DISABLED
        self.clk_drv = 0
        self.q_drv = 0
        self.d_drv = 0
        self.cs_drv = 0
        self.hd_drv = 0
        self.wp_drv = 0

        self.append_digest = True

        if load_file is not None:
            start = load_file.tell()

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)
            self.load_extended_header(load_file)

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            if self.append_digest:
                end = load_file.tell()
                self.stored_digest = load_file.read(32)
                load_file.seek(start)
                calc_digest = hashlib.sha256()
                calc_digest.update(load_file.read(end - start))
                self.calc_digest = calc_digest.digest()

    def is_flash_addr(self, addr):
        return (ESP32ROM.IROM_MAP_START <= addr < ESP32ROM.IROM_MAP_END) \
            or (ESP32ROM.DROM_MAP_START <= addr < ESP32ROM.DROM_MAP_END)

    def default_output_name(self, input_file):
        return "%s.bin" % (os.path.splitext(input_file)[0])

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        pass  # TODO: add warnings for ESP32 segment offset/size combinations that are wrong

    def save(self, filename):
        total_segments = 0
        with io.BytesIO() as f:
            self.write_common_header(f, self.segments)

            self.save_extended_header(f)

            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            
            flash_segments = [copy.deepcopy(s) for s in sorted(self.segments, key=lambda s:s.addr) if self.is_flash_addr(s.addr)]
            ram_segments = [copy.deepcopy(s) for s in sorted(self.segments, key=lambda s:s.addr) if not self.is_flash_addr(s.addr)]

            IROM_ALIGN = 65536
            if len(flash_segments) > 0:
                last_addr = flash_segments[0].addr
                for segment in flash_segments[1:]:
                    if segment.addr // IROM_ALIGN == last_addr // IROM_ALIGN:
                        raise FatalError(("Segment loaded at 0x%08x lands in same 64KB flash mapping as segment loaded at 0x%08x. " +
                                          "Can't generate binary. Suggest changing linker script or ELF to merge sections.") %
                                         (segment.addr, last_addr))
                    last_addr = segment.addr

            def get_alignment_data_needed(segment):
                align_past = (segment.addr % IROM_ALIGN) - self.SEG_HEADER_LEN
                pad_len = (IROM_ALIGN - (f.tell() % IROM_ALIGN)) + align_past
                if pad_len == 0 or pad_len == IROM_ALIGN:
                    return 0
                pad_len -= self.SEG_HEADER_LEN
                if pad_len < 0:
                    pad_len += IROM_ALIGN
                return pad_len

            while len(flash_segments) > 0:
                segment = flash_segments[0]
                pad_len = get_alignment_data_needed(segment)
                if pad_len > 0:
                    if len(ram_segments) > 0 and pad_len > self.SEG_HEADER_LEN:
                        pad_segment = ram_segments[0].split_image(pad_len)
                        if len(ram_segments[0].data) == 0:
                            ram_segments.pop(0)
                    else:
                        pad_segment = ImageSegment(0, b'\x00' * pad_len, f.tell())
                    checksum = self.save_segment(f, pad_segment, checksum)
                    total_segments += 1
                else:
                    assert (f.tell() + 8) % IROM_ALIGN == segment.addr % IROM_ALIGN
                    checksum = self.save_segment(f, segment, checksum)
                    flash_segments.pop(0)
                    total_segments += 1
            for segment in ram_segments:
                checksum = self.save_segment(f, segment, checksum)
                total_segments += 1

            self.append_checksum(f, checksum)
            image_length = f.tell()
            f.seek(1)
            try:
                f.write(chr(total_segments))
            except TypeError:
                f.write(bytes([total_segments]))

            if self.append_digest:
                f.seek(0)
                digest = hashlib.sha256()
                digest.update(f.read(image_length))
                f.write(digest.digest())

            with open(filename, 'wb') as real_file:
                real_file.write(f.getvalue())

    def load_extended_header(self, load_file):
        def split_byte(n):
            return (n & 0x0F, (n >> 4) & 0x0F)

        fields = list(struct.unpack(self.EXTENDED_HEADER_STRUCT_FMT, load_file.read(16)))

        self.wp_pin = fields[0]

        self.clk_drv, self.q_drv = split_byte(fields[1])
        self.d_drv, self.cs_drv = split_byte(fields[2])
        self.hd_drv, self.wp_drv = split_byte(fields[3])

        if fields[15] in [0, 1]:
            self.append_digest = (fields[15] == 1)
        else:
            raise RuntimeError("Invalid value for append_digest field (0x%02x). Should be 0 or 1.", fields[15])

        if any(f for f in fields[4:15] if f != 0):
            print("Warning: some reserved header fields have non-zero values. This image may be from a newer esptool.py?")

    def save_extended_header(self, save_file):
        def join_byte(ln,hn):
            return (ln & 0x0F) + ((hn & 0x0F) << 4)

        append_digest = 1 if self.append_digest else 0

        fields = [self.wp_pin,
                  join_byte(self.clk_drv, self.q_drv),
                  join_byte(self.d_drv, self.cs_drv),
                  join_byte(self.hd_drv, self.wp_drv)]
        fields += [0] * 11
        fields += [append_digest]

        packed = struct.pack(self.EXTENDED_HEADER_STRUCT_FMT, *fields)
        save_file.write(packed)


class ELFFile(object):
    SEC_TYPE_PROGBITS = 0x01
    SEC_TYPE_STRTAB = 0x03

    LEN_SEC_HEADER = 0x28

    def __init__(self, name):
        self.name = name
        with open(self.name, 'rb') as f:
            self._read_elf_file(f)

    def get_section(self, section_name):
        for s in self.sections:
            if s.name == section_name:
                return s
        raise ValueError("No section %s in ELF file" % section_name)

    def _read_elf_file(self, f):
        LEN_FILE_HEADER = 0x34
        try:
            (ident,_type,machine,_version,
             self.entrypoint,_phoff,shoff,_flags,
             _ehsize, _phentsize,_phnum, shentsize,
             shnum,shstrndx) = struct.unpack("<16sHHLLLLLHHHHHH", f.read(LEN_FILE_HEADER))
        except struct.error as e:
            raise FatalError("Failed to read a valid ELF header from %s: %s" % (self.name, e))

        if byte(ident, 0) != 0x7f or ident[1:4] != b'ELF':
            raise FatalError("%s has invalid ELF magic header" % self.name)
        if machine != 0x5e:
            raise FatalError("%s does not appear to be an Xtensa ELF file. e_machine=%04x" % (self.name, machine))
        if shentsize != self.LEN_SEC_HEADER:
            raise FatalError("%s has unexpected section header entry size 0x%x (not 0x28)" % (self.name, shentsize, self.LEN_SEC_HEADER))
        if shnum == 0:
            raise FatalError("%s has 0 section headers" % (self.name))
        self._read_sections(f, shoff, shnum, shstrndx)

    def _read_sections(self, f, section_header_offs, section_header_count, shstrndx):
        f.seek(section_header_offs)
        len_bytes = section_header_count * self.LEN_SEC_HEADER
        section_header = f.read(len_bytes)
        if len(section_header) == 0:
            raise FatalError("No section header found at offset %04x in ELF file." % section_header_offs)
        if len(section_header) != (len_bytes):
            raise FatalError("Only read 0x%x bytes from section header (expected 0x%x.) Truncated ELF file?" % (len(section_header), len_bytes))

        section_header_offsets = range(0, len(section_header), self.LEN_SEC_HEADER)

        def read_section_header(offs):
            name_offs,sec_type,_flags,lma,sec_offs,size = struct.unpack_from("<LLLLLL", section_header[offs:])
            return (name_offs, sec_type, lma, size, sec_offs)
        all_sections = [read_section_header(offs) for offs in section_header_offsets]
        prog_sections = [s for s in all_sections if s[1] == ELFFile.SEC_TYPE_PROGBITS]

        if not (shstrndx * self.LEN_SEC_HEADER) in section_header_offsets:
            raise FatalError("ELF file has no STRTAB section at shstrndx %d" % shstrndx)
        _,sec_type,_,sec_size,sec_offs = read_section_header(shstrndx * self.LEN_SEC_HEADER)
        if sec_type != ELFFile.SEC_TYPE_STRTAB:
            print('WARNING: ELF file has incorrect STRTAB section type 0x%02x' % sec_type)
        f.seek(sec_offs)
        string_table = f.read(sec_size)

        def lookup_string(offs):
            raw = string_table[offs:]
            return raw[:raw.index(b'\x00')]

        def read_data(offs,size):
            f.seek(offs)
            return f.read(size)

        prog_sections = [ELFSection(lookup_string(n_offs), lma, read_data(offs, size)) for (n_offs, _type, lma, size, offs) in prog_sections
                         if lma != 0]
        self.sections = prog_sections


def slip_reader(port, trace_function):
    partial_packet = None
    in_escape = False
    while True:
        waiting = port.inWaiting()
        read_bytes = port.read(1 if waiting == 0 else waiting)
        if read_bytes == b'':
            waiting_for = "header" if partial_packet is None else "content"
            trace_function("Timed out waiting for packet %s", waiting_for)
            raise FatalError("Timed out waiting for packet %s" % waiting_for)
        trace_function("Read %d bytes: %r", len(read_bytes), read_bytes)
        for b in read_bytes:
            if type(b) is int:
                b = bytes([b])

            if partial_packet is None:
                if b == b'\xc0':
                    partial_packet = b""
                else:
                    trace_function("Read invalid data: %r", read_bytes)
                    trace_function("Remaining data in serial buffer: %r", port.read(port.inWaiting()))
                    raise FatalError('Invalid head of packet (%r)' % b)
            elif in_escape:
                in_escape = False
                if b == b'\xdc':
                    partial_packet += b'\xc0'
                elif b == b'\xdd':
                    partial_packet += b'\xdb'
                else:
                    trace_function("Read invalid data: %r", read_bytes)
                    trace_function("Remaining data in serial buffer: %r", port.read(port.inWaiting()))
                    raise FatalError('Invalid SLIP escape (%r%r)' % (b'\xdb', b))
            elif b == b'\xdb':
                in_escape = True
            elif b == b'\xc0':
                trace_function("Full packet: %r", partial_packet)
                yield partial_packet
                partial_packet = None
            else:
                partial_packet += b


def arg_auto_int(x):
    return int(x, 0)


def div_roundup(a, b):
    return (int(a) + int(b) - 1) // int(b)


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


def hexify(s):
    if not PYTHON2:
        return ''.join('%02X' % c for c in s)
    else:
        return ''.join('%02X' % ord(c) for c in s)


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


def load_ram(esp, args):
    image = LoadFirmwareImage(esp, args.filename)

    print('RAM boot...')
    for (offset, size, data) in image.segments:
        print('Downloading %d bytes at %08x...' % (size, offset), end=' ')
        sys.stdout.flush()
        esp.mem_begin(size, div_roundup(size, esp.ESP_RAM_BLOCK), esp.ESP_RAM_BLOCK, offset)

        seq = 0
        while len(data) > 0:
            esp.mem_block(data[0:esp.ESP_RAM_BLOCK], seq)
            data = data[esp.ESP_RAM_BLOCK:]
            seq += 1
        print('done!')

    print('All segments done, executing at %08x' % image.entrypoint)
    esp.mem_finish(image.entrypoint)


def read_mem(esp, args):
    print('0x%08x = 0x%08x' % (args.address, esp.read_reg(args.address)))


def write_mem(esp, args):
    esp.write_reg(args.address, args.value, args.mask, 0)
    print('Wrote %08x, mask %08x to %08x' % (args.value, args.mask, args.address))


def dump_mem(esp, args):
    f = open(args.filename, 'wb')
    for i in range(args.size // 4):
        d = esp.read_reg(args.address + (i * 4))
        f.write(struct.pack(b'<I', d))
        if f.tell() % 1024 == 0:
            print('\r%d bytes read... (%d %%)' % (f.tell(),
                                                  f.tell() * 100 // args.size),
                  end=' ')
        sys.stdout.flush()
    print('Done!')


def detect_flash_size(esp, args):
    if args.flash_size == 'detect':
        flash_id = esp.flash_id()
        size_id = flash_id >> 16
        args.flash_size = DETECTED_FLASH_SIZES.get(size_id)
        if args.flash_size is None:
            print('Warning: Could not auto-detect Flash size (FlashID=0x%x, SizeID=0x%x), defaulting to 4MB' % (flash_id, size_id))
            args.flash_size = '4MB'
        else:
            print('Auto-detected Flash size:', args.flash_size)


def _update_image_flash_params(esp, address, args, image):
    if len(image) < 8:
        return image

    magic, _, flash_mode, flash_size_freq = struct.unpack("BBBB", image[:4])
    if address != esp.BOOTLOADER_FLASH_OFFSET or magic != esp.ESP_IMAGE_MAGIC:
        return image

    if args.flash_mode != 'keep':
        flash_mode = {'qio':0, 'qout':1, 'dio':2, 'dout': 3}[args.flash_mode]

    flash_freq = flash_size_freq & 0x0F
    if args.flash_freq != 'keep':
        flash_freq = {'40m':0, '26m':1, '20m':2, '80m': 0xf}[args.flash_freq]

    flash_size = flash_size_freq & 0xF0
    if args.flash_size != 'keep':
        flash_size = esp.parse_flash_size_arg(args.flash_size)

    flash_params = struct.pack(b'BB', flash_mode, flash_size + flash_freq)
    if flash_params != image[2:4]:
        print('Flash params set to 0x%04x' % struct.unpack(">H", flash_params))
        image = image[0:2] + flash_params + image[4:]
    return image


def write_flash(esp, args):
    if args.compress is None and not args.no_compress:
        args.compress = not args.no_stub

    flash_end = flash_size_bytes(args.flash_size)
    for address, argfile in args.addr_filename:
        argfile.seek(0,2)  # seek to end
        if address + argfile.tell() > flash_end:
            raise FatalError(("File %s (length %d) at offset %d will not fit in %d bytes of flash. " +
                             "Use --flash-size argument, or change flashing address.")
                             % (argfile.name, argfile.tell(), address, flash_end))
        argfile.seek(0)

    for address, argfile in args.addr_filename:
        if args.no_stub:
            print('Erasing flash...')
        image = pad_to(argfile.read(), 4)
        if len(image) == 0:
            print('WARNING: File %s is empty' % argfile.name)
            continue
        image = _update_image_flash_params(esp, address, args, image)
        calcmd5 = hashlib.md5(image).hexdigest()
        uncsize = len(image)
        if args.compress:
            uncimage = image
            image = zlib.compress(uncimage, 9)
            ratio = uncsize / len(image)
            blocks = esp.flash_defl_begin(uncsize, len(image), address)
        else:
            ratio = 1.0
            blocks = esp.flash_begin(uncsize, address)
        argfile.seek(0)
        seq = 0
        written = 0
        t = time.time()
        while len(image) > 0:
            print('\rWriting at 0x%08x... (%d %%)' % (address + seq * esp.FLASH_WRITE_SIZE, 100 * (seq + 1) // blocks), end='')
            sys.stdout.flush()
            block = image[0:esp.FLASH_WRITE_SIZE]
            if args.compress:
                esp.flash_defl_block(block, seq, timeout=DEFAULT_TIMEOUT * ratio)
            else:
                # Pad the last block
                block = block + b'\xff' * (esp.FLASH_WRITE_SIZE - len(block))
                esp.flash_block(block, seq)
            image = image[esp.FLASH_WRITE_SIZE:]
            seq += 1
            written += len(block)
        t = time.time() - t
        speed_msg = ""
        if args.compress:
            if t > 0.0:
                speed_msg = " (effective %.1f kbit/s)" % (uncsize / t * 8 / 1000)
            print('\rWrote %d bytes (%d compressed) at 0x%08x in %.1f seconds%s...' % (uncsize, written, address, t, speed_msg))
        else:
            if t > 0.0:
                speed_msg = " (%.1f kbit/s)" % (written / t * 8 / 1000)
            print('\rWrote %d bytes at 0x%08x in %.1f seconds%s...' % (written, address, t, speed_msg))
        try:
            res = esp.flash_md5sum(address, uncsize)
            if res != calcmd5:
                print('File  md5: %s' % calcmd5)
                print('Flash md5: %s' % res)
                print('MD5 of 0xFF is %s' % (hashlib.md5(b'\xFF' * uncsize).hexdigest()))
                raise FatalError("MD5 of file does not match data in flash!")
            else:
                print('Hash of data verified.')
        except NotImplementedInROMError:
            pass

    print('\nLeaving...')

    if esp.IS_STUB:
        esp.flash_begin(0, 0)
        if args.compress:
            esp.flash_defl_finish(False)
        else:
            esp.flash_finish(False)

    if args.verify:
        print('Verifying just-written flash...')
        print('(This option is deprecated, flash contents are now always read back after flashing.)')
        verify_flash(esp, args)


def image_info(args):
    image = LoadFirmwareImage(args.chip, args.filename)
    print('Image version: %d' % image.version)
    print('Entry point: %08x' % image.entrypoint if image.entrypoint != 0 else 'Entry point not set')
    print('%d segments' % len(image.segments))
    print
    idx = 0
    for seg in image.segments:
        idx += 1
        print('Segment %d: %r' % (idx, seg))
    calc_checksum = image.calculate_checksum()
    print('Checksum: %02x (%s)' % (image.checksum,
                                   'valid' if image.checksum == calc_checksum else 'invalid - calculated %02x' % calc_checksum))
    try:
        digest_msg = 'Not appended'
        if image.append_digest:
            is_valid = image.stored_digest == image.calc_digest
            digest_msg = "%s (%s)" % (hexify(image.calc_digest).lower(),
                                      "valid" if is_valid else "invalid")
            print('Validation Hash: %s' % digest_msg)
    except AttributeError:
        pass


def make_image(args):
    image = ESPFirmwareImage()
    if len(args.segfile) == 0:
        raise FatalError('No segments specified')
    if len(args.segfile) != len(args.segaddr):
        raise FatalError('Number of specified files does not match number of specified addresses')
    for (seg, addr) in zip(args.segfile, args.segaddr):
        data = open(seg, 'rb').read()
        image.segments.append(ImageSegment(addr, data))
    image.entrypoint = args.entrypoint
    image.save(args.output)


def elf2image(args):
    e = ELFFile(args.input)
    if args.chip == 'auto':
        print("Creating image for ESP8266...")
        args.chip = 'esp8266'

    if args.chip == 'esp32':
        image = ESP32FirmwareImage()
    elif args.version == '1':  # ESP8266
        image = ESPFirmwareImage()
    else:
        image = OTAFirmwareImage()
    image.entrypoint = e.entrypoint
    image.segments = e.sections
    image.flash_mode = {'qio':0, 'qout':1, 'dio':2, 'dout': 3}[args.flash_mode]
    image.flash_size_freq = image.ROM_LOADER.FLASH_SIZES[args.flash_size]
    image.flash_size_freq += {'40m':0, '26m':1, '20m':2, '80m': 0xf}[args.flash_freq]

    if args.output is None:
        args.output = image.default_output_name(args.input)
    image.save(args.output)


def read_mac(esp, args):
    mac = esp.read_mac()

    def print_mac(label, mac):
        print('%s: %s' % (label, ':'.join(map(lambda x: '%02x' % x, mac))))
    print_mac("MAC", mac)


def chip_id(esp, args):
    chipid = esp.chip_id()
    print('Chip ID: 0x%08x' % chipid)


def erase_flash(esp, args):
    print('Erasing flash (this may take a while)...')
    t = time.time()
    esp.erase_flash()
    print('Chip erase completed successfully in %.1fs' % (time.time() - t))


def erase_region(esp, args):
    print('Erasing region (may be slow depending on size)...')
    t = time.time()
    esp.erase_region(args.address, args.size)
    print('Erase completed successfully in %.1f seconds.' % (time.time() - t))


def run(esp, args):
    esp.run()


def flash_id(esp, args):
    flash_id = esp.flash_id()
    print('Manufacturer: %02x' % (flash_id & 0xff))
    flid_lowbyte = (flash_id >> 16) & 0xFF
    print('Device: %02x%02x' % ((flash_id >> 8) & 0xff, flid_lowbyte))
    print('Detected flash size: %s' % (DETECTED_FLASH_SIZES.get(flid_lowbyte, "Unknown")))


def read_flash(esp, args):
    if args.no_progress:
        flash_progress = None
    else:
        def flash_progress(progress, length):
            msg = '%d (%d %%)' % (progress, progress * 100.0 / length)
            padding = '\b' * len(msg)
            if progress == length:
                padding = '\n'
            sys.stdout.write(msg + padding)
            sys.stdout.flush()
    t = time.time()
    data = esp.read_flash(args.address, args.size, flash_progress)
    t = time.time() - t
    print('\rRead %d bytes at 0x%x in %.1f seconds (%.1f kbit/s)...'
          % (len(data), args.address, t, len(data) / t * 8 / 1000))
    open(args.filename, 'wb').write(data)


def verify_flash(esp, args):
    differences = False

    for address, argfile in args.addr_filename:
        image = pad_to(argfile.read(), 4)
        argfile.seek(0)

        image = _update_image_flash_params(esp, address, args, image)

        image_size = len(image)
        print('Verifying 0x%x (%d) bytes @ 0x%08x in flash against %s...' % (image_size, image_size, address, argfile.name))
        digest = esp.flash_md5sum(address, image_size)
        expected_digest = hashlib.md5(image).hexdigest()
        if digest == expected_digest:
            print('-- verify OK (digest matched)')
            continue
        else:
            differences = True
            if getattr(args, 'diff', 'no') != 'yes':
                print('-- verify FAILED (digest mismatch)')
                continue

        flash = esp.read_flash(address, image_size)
        assert flash != image
        diff = [i for i in range(image_size) if flash[i] != image[i]]
        print('-- verify FAILED: %d differences, first @ 0x%08x' % (len(diff), address + diff[0]))
        for d in diff:
            flash_byte = flash[d]
            image_byte = image[d]
            if PYTHON2:
                flash_byte = ord(flash_byte)
                image_byte = ord(image_byte)
            print('   %08x %02x %02x' % (address + d, flash_byte, image_byte))
    if differences:
        raise FatalError("Verify failed.")


def read_flash_status(esp, args):
    print('Status value: 0x%04x' % esp.read_status(args.bytes))


def write_flash_status(esp, args):
    fmt = "0x%%0%dx" % (args.bytes * 2)
    args.value = args.value & ((1 << (args.bytes * 8)) - 1)
    print(('Initial flash status: ' + fmt) % esp.read_status(args.bytes))
    print(('Setting flash status: ' + fmt) % args.value)
    esp.write_status(args.value, args.bytes, args.non_volatile)
    print(('After flash status:   ' + fmt) % esp.read_status(args.bytes))


def expand_file_arguments():
    new_args = []
    expanded = False
    for arg in sys.argv:
        if arg.startswith("@"):
            expanded = True
            with open(arg[1:],"r") as f:
                for line in f.readlines():
                    new_args += shlex.split(line)
        else:
            new_args.append(arg)
    if expanded:
        print("esptool.py %s" % (" ".join(new_args[1:])))
        sys.argv = new_args


class FlashSizeAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=1, auto_detect=False, **kwargs):
        super(FlashSizeAction, self).__init__(option_strings, dest, nargs, **kwargs)
        self._auto_detect = auto_detect

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            value = {
                '2m': '256KB',
                '4m': '512KB',
                '8m': '1MB',
                '16m': '2MB',
                '32m': '4MB',
                '16m-c1': '2MB-c1',
                '32m-c1': '4MB-c1',
            }[values[0]]
            print("WARNING: Flash size arguments in megabits like '%s' are deprecated." % (values[0]))
            print("Please use the equivalent size '%s'." % (value))
            print("Megabit arguments may be removed in a future release.")
        except KeyError:
            value = values[0]

        known_sizes = dict(ESP8266ROM.FLASH_SIZES)
        known_sizes.update(ESP32ROM.FLASH_SIZES)
        if self._auto_detect:
            known_sizes['detect'] = 'detect'
        if value not in known_sizes:
            raise argparse.ArgumentError(self, '%s is not a known flash size. Known sizes: %s' % (value, ", ".join(known_sizes.keys())))
        setattr(namespace, self.dest, value)


class SpiConnectionAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if value.upper() == "SPI":
            value = 0
        elif value.upper() == "HSPI":
            value = 1
        elif "," in value:
            values = value.split(",")
            if len(values) != 5:
                raise argparse.ArgumentError(self, '%s is not a valid list of comma-separate pin numbers. Must be 5 numbers - CLK,Q,D,HD,CS.' % value)
            try:
                values = tuple(int(v,0) for v in values)
            except ValueError:
                raise argparse.ArgumentError(self, '%s is not a valid argument. All pins must be numeric values' % values)
            if any([v for v in values if v > 33 or v < 0]):
                raise argparse.ArgumentError(self, 'Pin numbers must be in the range 0-33.')
            clk,q,d,hd,cs = values
            value = (hd << 24) | (cs << 18) | (d << 12) | (q << 6) | clk
        else:
            raise argparse.ArgumentError(self, '%s is not a valid spi-connection value. ' +
                                         'Values are SPI, HSPI, or a sequence of 5 pin numbers CLK,Q,D,HD,CS).' % value)
        setattr(namespace, self.dest, value)


class AddrFilenamePairAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs='+', **kwargs):
        super(AddrFilenamePairAction, self).__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        pairs = []
        for i in range(0,len(values),2):
            try:
                address = int(values[i],0)
            except ValueError as e:
                raise argparse.ArgumentError(self,'Address "%s" must be a number' % values[i])
            try:
                argfile = open(values[i + 1], 'rb')
            except IOError as e:
                raise argparse.ArgumentError(self, e)
            except IndexError:
                raise argparse.ArgumentError(self,'Must be pairs of an address and the binary filename to write there')
            pairs.append((address, argfile))

        end = 0
        for address, argfile in sorted(pairs):
            argfile.seek(0,2)  # seek to end
            size = argfile.tell()
            argfile.seek(0)
            sector_start = address & ~(ESPLoader.FLASH_SECTOR_SIZE - 1)
            sector_end = ((address + size + ESPLoader.FLASH_SECTOR_SIZE - 1) & ~(ESPLoader.FLASH_SECTOR_SIZE - 1)) - 1
            if sector_start < end:
                message = 'Detected overlap at address: 0x%x for file: %s' % (address, argfile.name)
                raise argparse.ArgumentError(self, message)
            end = sector_end
        setattr(namespace, self.dest, pairs)


ESP8266ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
eNrNPXt/1Da2X2XshJCEASzb40cIy2QShkdhG6BJQ3/TbWzZhlJgkyG7SVn2fvbr85Jkz4RA2e69f4SObFk6Ou9zdKT+6/pZfXF2fWtQXp9dFNnsQgWziyAYt/+o2UXTwN/0Pjzq/mXtX1Pf+/7hzqP2u7j9K6Hr\
vfat5kZ9j7plzme67alymGVMPenFcW8Ctfy3cvoQaA5AujsTzdCD2n40Xrqc2UWub/A6ikB+tdNedwaOHajNgAxJBxO9hgxXdrDVQdBgw4G1JUZWIVhHDoBAI/N1Do3aaeQG8bHzBj5WpR26CGbzHnIyA8LsTH7u\
t//UTkOFzhDaAaMMnIZqzCK228c5AxS4oAKxisqBLnCgCzovNc1l5lEjB0WqywNB4LAeNmT2UguNWsJnmdMobOMIvxoPn+B/gjv4n4uHhl0e868yfsS/tL7Fv1Q7QR1yo8py/PXaPGsHqWTGvAWsRq4eP1kTkHhI\
j0CFReXtl4UipodPVPtbB36x4iMBacFhsds+DYtJO35Y7MB8RTtcExb3SHTqlEbTBkUwRQgP27dlxAgE9ABfJ67AAUjhd34KvTOeNdObHvRvpw1aSpTQWXlC2nYeJcRT8nBzCNMPWAEAZsKJLEHWMqJ5q2IJtEjE\
hrERKDMYECYM4oF5gEMP4R8eLe6PdtlzgBVxsiM/nrU/EDmn8oOxFJYMCA+mm2WDoa7xSCabZis0MK63/7TDqWQunwliMnpDk5gXG/apisId4JSQOyn/2S4+GfmFDwwD4wKd8G0U2rEywLNSgT9oJrOz9WEHmrD9\
msmgeU1l2V+TUB/UNzQyGBYpl90nBKG5kDkj352cBlNqAD8GLVYyZsomJV5UKbFAXuGyaOS6ZmDUJcAItEWzSGbdMnJVMd8Qtui/VQi6HFCFSE4AffBJGj5rBOD2Yc56r0k+rDTYefqzPNmdvW9WpOsTnjNh6A0M\
zS5+dYq/XzjTRRbCPOtqvbwDXJB8JMgAy80HZwgxWgl3Dhr5anphRyud0abv4Pm0/YbVpdI9ROQ013pDWoFWN5bO8KAF5D2N3PTgvGWRAKSVT5QLwESe+87DlwJV6NC1UtBDRcN2wjN5FtAz4HCA9t89XuiSNUuu\
ue+i7jtSrcHIxZWqQJmD8UIUz1glJcYWNow64gN8d+pqld8XebBulVldgUtBpjNL3hkjO9yBj/7Z/+iQYFMFrog4GFd/i3pl+ukAeDA+fAGGjRVmCPbkLuuohDW59SlA7FC/vl+Y7jnhsw5oLo1z3eYf6V9oDTAH\
mrHFoWkZzWXLSJYu45AtRA2o/tHSAHyNKhTZXjMIPxJuLxnzQpCyEZIeC03uLLy6R6908leX2mvSZfoUHmdPvA1Hx7uAhMJ4jrxP7/B8MFbM06mwHWXly0aZig7YooEAQ0E83XGR2+pJVbvDhSxugTNuQhbeijG6\
MNkQfJDnxBpooIBpwI5oqzx5mBwMBbK+mPi6mdqZ6mJ3YskOTmRdj30YLr0F4z9n6EaleBET/oGK6gD0vqjg9PgArc4ePNzfG0AHtBzjaABwaTEqWsmaByi+LZDTGw5eAGWAF4sGBzcqiWZnoFDM2+yQdVoWshZC\
5OhkYHVVRgqEeGJgyYsOMLLMdGBY73vstSpMRwLb4bsANdCIKNQJZ/hr4ILV7jSW90lLqbTzmeFY35kXRwa3ryGBsgS/IKppnXbZpdF/V6SXGnfO/DU5Gk2aDOHzAQU6Lky5YRRyy3PWpgHCudk2cvats+98agWj\
zR8H1Esjz4Cqal4SaNghmgoDGQ3Lq48dGasslhYRStpJXGKBGPkjGIACH31gXxibejR3vAzthJgLSqwEnViKL6NkFnBbVNhaqQjFfyIkRzPVLq0pnSewhHgN+XMKLNaAdBG/AOetpGyO2rcXGh7HoZg0nOYR29Io\
5QAMB/YY2sSOhZIBXmRTW28MlayrUpAFauMAArVCeAwSVQ8idO/AhY4GKyAUrjtd6/54d+HlTYwlFdmK7nufXMM64w5Jv4PlYhvG4fQ0cTSBf+MjsMfZ6B8wCrMLdV/ubkboa0YDYFfgaFQtyLf3f2JiJ/TXjR0/\
7zn7qMVJk1qNWdxgDq0ddyyWoAWiPEF4GfrMoIqCzqYumZ8iH93JuXejLK5RlMvW+HrKulfELsQOYQFcNXrCDnLojU6Z6WvgJu/GyXdsw4s9iq3Bca+K38piAwcZjo84sCzIfwZ5Vqiu3sKM5xQDkEl5SzCAs1rr\
+ZA+zIBAarT+FiYs1ubFKg68uf0CtOsnkEnoEL8GjQN8X0ZWKCADFMSK4tqmJpu0Tu8RIyFzK4Dd1D1NDByVk9TAf7MwB2HJKXIr0ns5RsGr7+iT9ucaezhgTVrsgGbWKwFmobx/MdI00w4t+qPyZ0Kbrig50JL2\
PWGhSEkP1xiGIf94/6AxwDjqJidvFtXUiKNSfMBDWS8qtGmjzqcLwKN3UMPc2xtTJ8bBEee0nmv7Ka7nV7seFb2kdUxvOekRgX9k4a968OehcQBEFAKvcDpp7OT9wo9AHiPIUYWv2SoE10Bq3viTInhexGVxG4gD\
qoBZV5H2X1AGCPXEC557cenhR15EDE4SV5M+GjTEhFr/c38Qi2RmAwyv9n+AmLg84OHC00PmIUweYUSDIfyr1OI/GI3HkJkRvyMZg8xEQQMco1nnqGQB+d4ujD3czRnR5K0EkatWmJWa5O6YSMjM4b40fMbc6Q/W\
WT41LS7QkYc6Iy+FSWkYzKdEDl1DIaQvy+M5bG7Ht6lXIif/rsaitCFUr0FcspLZL2EfA0c8vUUobQ3qarucMh14O7CslAStjnbIDsOymuoQqLCC1ngVNUF1BxGx+hlE5AYRG5z21S8OyQA2BbsdcY+js+Urn7r+\
wh9YetZZOi+Ds29jXjBQSn0C+g3oIxVYL1glT9llBf6sclz8yqWLn8vKMWTAcfQhW/N4+uXr/kaKw7IbSWMFMVszUENN/cbf8oHVJmSVDKk5lKyzHVl5Lzebbu98OfeDVwBKgkNoyuTMNzSNUHJsZBWyR3FuU3EY\
1dRGxb3xH/uCJYKap7b+a/sR+G1N9SZ6HPm70Mcg22PnB0YG56+pjF6EkQUPgloF8DTJ1PECQ87pKrAjYPnPcr+NUkBVUmqsaR2Mszvh7GzLdTokJVoFPiZAcnZc0EHWCygcfphKxlmSVcBx24j5a1/KcdvRIdlS\
8Nf0QtDvoDz503RNE1iBq3GL5Az9izWHwyzbOfFqEGzvTmnhQbioVFptkgP0wCfB3IP0e9nM7wuAB9bzI1v0lBpVsAv+wfEKegnXyTGBVBcSoupl8SCmqcslAGQIQGYAYERxnGd03hAcpjOMCT5aP38J4YZgpNrJ\
ymyJNCGVIOPZ0ndjH4DWGO98hH/OKfEaKEikhdBKpJXcBG0Frr2G1adkwOfoXPVseJWQeFobPvdCsd1ktcGCw4z648FJw9kfIE6TcfYC0d3K9nzaj+t668FtoYgTp8gaazYiyiAiEn7yX4H4DMUTB1aqJvAsFP9y\
9JlFQfJhYVGSGsk2zxWxEHSxS2xX3K4bMJfK3kY22RW2is7Ju8T4V4cntLEnef08nkhytPQ5HGxSX7YZZBsIaKzP+gHw5KH5lCQsy2QI8PBgB6bOtjguhzxHKuM1mw/ne/ZjdtExU4iJSuVk5gC74Jq22hH2CljY\
HFt+7WucGkxOi5LR+v9MydRoQrwTIiYJvLO+nff8AoYKcShwtNR4yhQGfNUYbgYDm0Bd4hk8RFY8guEeR4M1+By2kSDuRVtRJgmiqbKQtLEvgv0cN5H7vnPUZ1GhU8uErtc8Zb5xt8CTu9tXkmyJ+wVu3SFZFx3+\
P7AL3hM0yFt9pmxRHqxurkJZAqDIuqHWThsftUW+h6gE+VZRmpCFVTpC8kQ4J2z9q9MdlzQncyAXCvr45AKs0xy83yOIRNSeRDytuVIu7eYFjXW0qF9m13dQpdC6N2fXnYRWoF70P/CY/i2ZcEgEanNjQiUHuD2k\
/rrIIi2HqZZB1iFNhCoaqzN4qiwE6VR+cRMhv2UtoRuEZYmbgxfgN3GPKnI1EYpKMFkRLt+baPrZAnGLbCAG8LHMA4ymYLdTPXUNMJt/zOnMEb1tqyAVnGdgJaGVgVIufE720IzRBlE7L/Z4T6se2eWid4kZ2NB5\
GLDux61A3TpjvsAxIA0Of4C1HLMHn8grBTe3yTkkvcRSRx67jhoiONzFy2RyJGJeZLwPJnhMWHgx2IXqCdzxli3idFKgmO3BLn00L7KTdMBJfqXCIg29ZOKlCEo895KwWB9Hg4mXnZwi4+/Ni2RSZA8orwOGHO0r\
uDRpGpw8JCzmwZ7N2I/HalKs2/ATgcx4ixDrTTA7h+BP2jWNP8AAE28daBRNfoTWXHbTQVWk5CahD9XIV8EJWMTxOX7LdMZQv/JxBOQOCfnrIN8RfDDusZAkbFd+Ais/2QMRADql4wfIq/AER67i2Vm7HpgjlnQC\
CFALsP8D6vSJSfrVLQYBa+ct1tqfgdppMQySr405S9mzLOdeCvNlJ4h6zMEHQRawcOYIxBjZ6CSiteXhC6sJ89yVEcyUsbotKykM8W6ubdhMeZHa7eCsstYAVHXFO+zUV7aeIVkPkBeJL682JD8cEvfX6JHGp1xQ\
ozdXTnxGnNnPYbYAockl96nGj5TIzAOCWbbe3eoG7JCOaWM25Wdm34QXY4qCNLkKtJgNytOgB60/kSfp2FxM44C46ABSOkH8GLBcRITs0Kb5gOfriAPVcnKjdYHA6UUnLub4N5EYE5IV3eKYz8fsGJxFhzDd6L8X\
s1uqh07smToxhNlSMjSc2PqIrLzZmSOylS7s/6zirCsDmvgGQSUmVgH/AGlc/vndZZ7QZR5UVMFAmAetd5ArGDujUqT31s7kkjHUzA4xU16V4oTElvzgaBry+2gaCACfJ0Lyw9YlqhMOKppUfAsf4sxWCNdMuQNN\
EXW8OmfTHL1qpTzorNU7+JdyJOglKMkJaNqfRhFe64eaE0rmNQGGZKA8s+g4FPlISeciX2XvxHIUa1dFTUobR2aG3u5bQiJBkGPpD+1rGBfKLzhNd++KNN0Srl/hJF0WL7qIhvnTKxJ1DudrjhAC8hxWF2XA8l+Q\
GXlI78JU6HFroWROn2vaWM0K3o5ROY51DmMt4gLgOgeCn8MKN8+9CQy5g/uom2uPaYyzDluQTifO4AGVFg3YYLB+ph4ji+xt7YWEI3VVrD2jpVh3rnXgKNj+2PQ8/m5EcApekZ4giRSGeSrcJAInUhnUNK9YMDi/\
RItfYKUXoBZ9LO5D7QtobfRihh8XEKgHfZhbgKWqgSsi1IQhij6Ch6RKeoUbd4g1Ne4Pshh2e+AGNrD1ianyMsrpF3iFAfpc67QzCiofQCvRk31hRcdYxDqZsJbUZB3Q5kRcfZmMjPhu7OdiQ1dE135vtzQbLmQ0\
FlYn65g55yxjiclz0JAds1r+SWY1E7OqLzWrm6xQsew0pl3IP2pWEaS0Y1ZHS8wqp4SvfY2C+cB7lewTAaRNtczCJv8dC6v/JAvLGiVcNLKQQe+y0Fhsm2UhjIIGx8xC6EwFgw11fMypy8RUeWNW7RNZv8yhvSpX\
OlYPddvxK/Rm0dxuQWqnaMbgkQJe80QYYGpqA/qGdSEzMnA0JVVtvBKHdfrIipOp7dEUC2LmMF6ea+pkWEs3tZslNqGDhISN4xQCt9zW1FqekEqClcFlfLFAG44jy8DQBgqKAZJyy++QKXDIFKiWNKydIivIQAlV\
rn7ibHbPxwkSVxbnlnBogUD9lB9RNhcF9IU4PkKfkdDnnbN5eQmhuMTTFJyt9gMOsHf5ZCk+UbENVr8cn5MFfJ5y9XD52L80IIHHCusS2kjrkeSpcwezqcmdqPLBJ8fDS3HRJ2LHsSjtBCPJjzCbgnKB0iD7o3Eq\
rWfpY5anQjuCrhzs2TVYce63M4buWZq4g+JxD8VSLFEevLO04m15GUndOJi+EuqRdDey+wEbA4VgmCrxG6mpQOXR0CY9F4GvSo63fFPCo6QEf0kl4KgmIJXVHsMhOwsBSnp2mdpeQRPAm9gFG/Q8mnqOFC51C8Oe\
xrYZ77CvsY27c5M3xvo+ImtY0t9Bxz8sOj5h1HEHRTE7KV7Xr1vi9kmqyHUaiGix+BhbPY9BJ5voE+wJQTBkMhYVSwkaSURqLgJU6njMah2YMFDHv4pnEL9iz8Cer+i6CCo9xmLRB1aAM6TvMs/ArGMTlvcDwOhG\
22QVjpFxH8LCgPuC+M0eZtxMliWPRevsiU+gb0TpXdljSvouwQKPuXb1SjbLmM0K3IPT5DsaDsv/AxzW561gmYeAuHPOGFSjz3oIpeshPL3UQ4jHXC5fYMXscpV5ylUSlzLUxGWorqtJZxNalSkZPesn5FiU3zCk\
RWLCb8FPYvmB3ETmh0vdxF2hdrzES7hEM+5wtVEpUqm29nBzZVKs7lApJLwDLbAV44Ea3DJWyWt7OqGsJl/OYwsFY102Kzl/VCb/cU4rr1Zkr0CL6fmCCks7H1CqwVFkshto7Z3g+cSxQIg4sILgZzVFiSE09IJS\
rDaSg9J/qAhpimOMhE5wbIwKwmIz2B38KDpw//6AHLPNvQdwWgiLVqXCr8Ihhi8oK47nQLdfQB6ypiAq0Kt5Of1lOWGc3fw6n3ubTqg/xDw9bnorOxq5X8HmihPgq/LcR6M8LzbR2oqgl6VUHLUBhjkvOREXqeRk\
QTW57z5X2FTSDO9E+CC8cwBik0iGUfReKnEiJ/wxKMHxCagGiDeShwofqjcH7Ksrq7uLwpa50bE5cAQgX4/udMqFISFv7wK32oKsv2AghntJX5zkHBJMFI1Nf+NUy2U5n9GfEo5ps4v7h2uzeHWxFMvcRVSsffl+\
9pB3hQgPh4t4uCok/dYCNd0rUKMy9yVFWVNr4b9u/3dI7oANvKHsUf+nom51TsKpyuYhT8R2CafH/SL0NFNOaJey1g7U3ilqkpW8tOdZs8u5GQxYjNnQAuuAyHNsF94qgSqfg7iA6xX/Dr9+pRAhw0eYAIIfo098\
6AI4j3NUEKroESeTUvZ/EGdIwCMgjGJHu9gn0jSoEfT+PoRiVDLb2e2vCD82BfZv9t1kQ1r/TjWznAJc723LO5uKeCatcJ6pn/5GugPEyDyFndniYMmL6LIX8WUvRpe9SC57kfZeYCNDP7SIztGJPlnZAVT7hG88\
fh4cd6rA3ANBpb9lRtrcEh/5HNbSoMsAe95B3WIeE5e0b99asdtEhefkZ7/pU6FFuHpJD+uKTkLwQeam33Xu0UYvV+ufkAWmQzXe7dNn0L8l4c9MV/36LrFqCed/tRz0kmPIdKoKGBXnLg5ekrjXrMgqTh7ALlMR\
fiLNjzpAGJP3/UFv4UcZC2jUyx6LJgt6hc9yZA3236oa9uTBQ7ixjlW+jRwk9OUQAp/GUXA6rthYyWbz0xVGEfxFJ9t2J1WNSjlUgUUyFeqD42vsnZZ/2//bYP8XPlyVz+b7PqhCPWfI0pvEQdkoMgfOsVrDu8Hn\
yoQ4+iElBrJazpXgF+vbYBUmjlmuRYJr8i61ye/KGaJ0A/Lz2sEgVjXVMJY2ShPK5Qv5JGPMGoaFvmxDMNlveubt4NOf2BsK4PA2d4PdjcLjqh54qTb7fAcPby8+1JAC4vE6ID5z+iJk033puHT8AV1rkDlleciS\
dABxGzjt5gB29GCXLjPnYEmJCi5zdM7Wh9C/VZ0zJx4N+1d4OIeDgP6j3qEve4jAHBxkzs44eCHlgN/7fLap4rNGVBl4m8tA0LfNW6EUrwGe5RrDqBtgIlYGf6WVw3rwxDyu4eGTo9ns9duLTwgJH43CupIeEUhn\
yCkFPqISWpCRxQr+VlMCq1fwNeeeseUORKJzHYJzvJBPkeAXEfMOOsb5w9ksGz6So2A4V24TUBSb75CwYhoNZfPIOaumM6gfiLm4u8n3QxZXPLyH73h1grBaYA7hDIV714UOPbzNwsPbLDy8zcK7RznNlghzLpzl\
G1KIRY7Zqwvdy2TCZTfLZILNpnslw2Cwejjhayuw6hwW3BSdjngXg2eddn78qHNhA95KcXjW6eFc7aBCim8HK4FZSuZcKKOW34kDcbW5QCaL3TtjxuYqmydUT4MXnqjOpxl96sCO8q7Yd8nldpGBHI/FJZ3Bs9zz\
mF86t1XIaTaqKT4DnfkJP2hUpysebUN5Qg91AK5pNvpeClv52GoO12EEkeLkLhT10I+2/3iXVssDHjGj1XizxuNI0hmIhwZT5hWkHprYfFJiwvvxfQvUHs9PX3os7Q0yVUy7Z9veBQCgLhgedNTcmzzwwOwzsrbt\
gqU6n7M8TbPAOhagl3LwNRQkmsdxl9uUnB3Y8m0qjzvg2Wu+OwePiOA9ObyDiylvSPdWUjGZdSgsdUWZR+TGmjnmCRW4UuZekdRVxmO7TJu4cUXS4TEdFjyjei3J+ALPPg55B5z3ZoP0PrNxw4YYS7tGfL60oZ5Y\
4AzLw5OUyHNxB+F5RyiRnw8/QI/1J1zUEc2ur9i9XhXuvGC4jBlfHw4GsRy9qXccCEgBDgveaWnGBx0JCjGnGgSrhxFDV2MCEB23wDS7/KAoWHAeT3SHPbD6jzRL9mSAfJA/yYZb/sZQyAvUvIyKT+T6IulQo3cB\
Vknt0NKr/NlDMNotv5+dIvdbM4XmA/aUseAGousKrt5Ryc8cPWecmyu4hDLASomuAwl3rZAuATLUlAh6T8+rpk/evovE/s910hs1h4ONCQchHNfgOddPzZlkvXgvR6alnF/HrW+FX23ehEBXgzdUsaVC1zXfBtSe\
AmrhJozsGZ89aTIjLwNBs3sPWBDsXOOiUCsErE/Fz32OWiiYzXZerj4TYwNfxBsxljnEP/lG7DXetaHzHzbgK3V/iT+QqbtcG4lrGwVD9sw+xxUugHJfSomQBmq7P4l0wFx1vhSEL5upncBcLCAH4Ef3mXHkkOxI\
jATCJN3wLHlwGWRYF3HrqyHrQUdUYrOIVEMh2GLG+FzGCjmcORK2T/DkWuzK59XadlFAK5ewLfZOw8LeQKUWnEPE0U0CThuAejceQG3xIpqE1Xu8TR2OXL/itds4cRtnbuPCbXzq3uGX9e70y/tt96I2rOXOzHVr\
3+Gv2Dyr7jjX+uW53LVm3DkXrXxpDioGwC8oPNR2oPVaJeheuAa7CnijHZyBkVwjhgHsr6rCR2Mjt2o0HFYoTFw5gQmF58+ZYZrwLd/dsFRNeXScFrN3nRreJ7JDwBtGdb7k06pmD5ZyBpvPYKo98S+SbelayC1Z\
uMrX9oxFlcglQHTSEk97YQChSDDwhjR2fWCpcq9ZcfC7bO0po4WrheUVtmqmnfiCE+LaXiLzlnOziThpO+IJ3WT2LfZgpvjuDI7vkXeJaOlNHfanfsa3ZDQ2M9FCfcRZjaJ+xjJDz3+F5wUTw4HW48sl8BFtoWMq\
HQr8CjlF1pzcFhaKMjGfoa3crmq7LVgLUuVgazv5pHbumQuX4LA0C2g4hQP6h26FeUbnAuX+IEXUecj39uF2rDkPhxXyo8FBgJmVmK9jCzBTaPnjceKbI2177sFoSDFFrKDLfG0PQoYCHdC7PDlWWy69zM2z9+sp\
LUwE2xzkIzn3j+C32cI9b7hBiddSFOZsx7lclmMWuMN5hsYG3C0HTXC34EHqqNcggJtPUAulpUOqmK9uqStzlJdu22xMaPrFngJ+q/pa6YuUUS2mQNSPlpOEzpguhhr1mzltyXu5sk2tOWtvhBsFqO4KULbEg2oQ\
gwaIuzxE8HTg3O3Q+6bibG4l2bHgEE9weR/5lj5Hn/IoowVeOV9gFBJW0iU3+xlLJCkUnaizP0Yo6x88F+OJXviP7IyUlptyOJtpjjIFEaVdcZw1uc1obZXPQJlai4m4N3AQJ9zEPZcNiQ47J/ekp8aeszOZGXtT\
5rkDtPSvlvW3np75hqqgsHl9OMBbgX/5cFbM4W5gFaRxmgetV9q+qd+fzX93H8btw6o4K+ASYd+96BZ1yMjZEHQy/FRDwn+ICnbnVTB+a37xBaPU+DsXkIhdV9JH9u6VuAkB3mM8fm9+dT4oZmf8sJU5+Zk3EIcs\
ju007hCki32QuLWM2ZjGdTm89ZlB+Yaopd0qPpfUNv7FPiPOwHxK+IlYteMtsnwy64oZL2+UJV0DtPgmC0yDNwbaX7mDd5RH+TRLDWKrxFDhf8xDRBCNdvT1UH5zg/Ih2BgZmPBaallA/4axhUx01Gv3jsJ2z0i6\
RT9UOtZp9e5iVr258QyYay8D96pZ2+jcHlj0kje9MbVacuO26vXv38Id9tpRrx332kmvnfXauttWPXg6J5fVwG10erpXeavjxUu//7Q/dUU7/EoeuoqnruKxfju5op1e0c4+2z77TOv9Z1rdu76XtfVn2/PPyc6V\
f18rt8lX4ejsK9bdh7y5Qgv0IFc9SFQPi6oz3orbuOE2OsPecRu7buOF2+gQ5ENP0/TgLHpt3WvX0RIpUf9FKf6ztcC3aolv1SLfqmW+VQtd1f7KPxXY9JmRQHQ3+MToiCUtNhsmc8Ya5zGMpKnL/08Tiyv12ct1\
neIoDdsQM/v3/wLWvxs5\
""")))
ESP32ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
S0yomEyqQut//QdAk8Ky\
""")))