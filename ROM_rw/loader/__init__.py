from ..utils import (
    MAX_UINT24,
    MAX_TIMEOUT,
    DEFAULT_TIMEOUT,
    SYNC_TIMEOUT,
    MD5_TIMEOUT_PER_MB,
    CHIP_ERASE_TIMEOUT,
    ERASE_REGION_TIMEOUT_PER_MB,
    FatalError,
    basestring,
    byte,
    pad_to,
    hexify,
    timeout_per_mb,
    stub_function_only,
    check_supported_function,
    stub_and_esp32_function_only,
)

from ..utils.slip_reader import slip_reader
import time
import sys
import struct
import serial
import hashlib
import base64
import zlib

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
class ESPBOOTLOADER(object):
    IMAGE_V2_MAGIC = 0xea
    IMAGE_V2_SEGMENT = 4
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

ESP32ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
S0yomEyqQut//QdAk8Ky\
""")))

def esp8266_function_only(func):
    return check_supported_function(func, lambda o: o.CHIP_NAME == "ESP8266")
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
ESP8266ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
neIoDdsQM/v3/wLWvxs5\
""")))
__all__ = [
    'ESPLoader',
    'ESP8266ROM',
    'ESP32ROM',
    'ESP32StubLoader',
    'ESPBOOTLOADER'
]