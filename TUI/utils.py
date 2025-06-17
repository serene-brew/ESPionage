from ROM_rw import ESPLoader, FatalError, write_flash
from argparse import Namespace
import time

def read_esp_flash(port_name, baud_rate, start_address, end_address, firmware_name):
    try:
        time.sleep(3)
        esp = ESPLoader.detect_chip(port_name, baud_rate)
        time.sleep(2)
        esp.connect()
        esp = esp.run_stub()
        
        print('\033[32m[+] Reading flash memory from target\033[0m')
        time.sleep(1)

        address = start_address
        size = end_address

        def progress_callback(progress, length):
            percentage = (progress * 100) // length
            print(f"\r[~] Read progress: {percentage}%", end="")
        
        data = esp.read_flash(address, size, progress_callback)
        
        filename = firmware_name
        with open(filename, "wb") as f:
            f.write(data)
            
        print(f"\n[+] Flash read Saved to {filename}")
        return data
        
    except FatalError as e:
        print(f'\033[33m[!] Failed to read flash: {e}\033[0m')
        return None
    print("============================================================")
def write_esp_flash(port, baud, offset, firmware_path, erase_eeprom):
    try:
        esp = ESPLoader.detect_chip(port, baud)
        time.sleep(2)
        esp.connect()

        flash_id = esp.flash_id()
        detected_size = flash_id & 0xff
        flash_sizes = {
            0x12: '256KB',
            0x13: '512KB',
            0x14: '1MB',
            0x15: '2MB',
            0x16: '4MB',
            0x17: '8MB',
            0x18: '16MB'
        }
        flash_size = flash_sizes.get(detected_size, '4MB')
        print(f'[+] Detected flash size: {flash_size}')
        time.sleep(1)
        esp = esp.run_stub()
        
        if erase_eeprom == "Yes":
            print('[+] Erasing EEPROM contents from target')
            esp.erase_flash()
            print('[+] EEPROM erase complete')
        else:
            print('[+] Skipping EEPROM erase from target')
        args = Namespace()
        args.addr_filename = [(offset, open(firmware_path, 'rb'))]
        args.no_progress = False
        args.verify = False
        args.compress = True
        args.no_compress = False
        args.flash_mode = 'keep'
        args.flash_freq = 'keep'
        args.flash_size = flash_size
        args.no_stub = False
        
        print(f'\n[+] Writing firmware to {esp.CHIP_NAME} at address 0x{offset:X}')
        write_flash(esp, args)
        
        print(f"\n[+]Firmware successfully written to {esp.CHIP_NAME}")
        
        args.addr_filename[0][1].close()
        print("============================================================")
        return True
        
    except FatalError as e:
        print(f'\033[33m[!] Failed to write flash: {e}\033[0m')
        return False
    except FileNotFoundError:
        print(f'\033[33m[!] Firmware file not found: {firmware_path}\033[0m')
        return False
    except Exception as e:
        print(f'\033[33m[!] Unexpected error: {str(e)}\033[0m')
        return False
