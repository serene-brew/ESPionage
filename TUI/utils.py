from ROM_rw.dumper import ESP8266ROM, FatalError, write_flash
from argparse import Namespace

def read_esp_flash(port_name, baud_rate, start_address, end_address, firmware_name):
    import sys
    try:
        esp = ESP8266ROM(port=port_name, baud=baud_rate)
        esp.connect()
        esp = esp.run_stub()

        print('Reading flash...')
        address = start_address
        size = end_address

        def progress_callback(progress, length):
            percentage = (progress * 100) // length
            print(f"\rRead progress: {percentage}%", end="", flush=True)
        data = esp.read_flash(address, size, progress_callback)
        with open(firmware_name, "wb") as f:
            f.write(data)
        print("\nFlash read complete! Saved to ", firmware_name)
    except FatalError as e:
        print(f'Failed to read flash: {e}')

def write_esp_flash(firmware_path, port_name, baud_rate, flash_size, address=0x0, erase_eeprom="no"):
    try:
        esp = ESP8266ROM(port=port_name, baud=baud_rate)
        esp.connect()
        esp = esp.run_stub()
        
        if erase_eeprom == "yes":
            print('Erasing EEPROM...')
            esp.erase_flash()
            print('EEPROM erased successfully.')
        else:
            print('Skipping EEPROM erase.')

        args = Namespace()
        args.addr_filename = [(address, open(firmware_path, 'rb'))]
        args.no_progress = False
        args.verify = False
        args.compress = None
        args.no_compress = False
        args.flash_mode = 'keep'
        args.flash_freq = 'keep'
        args.flash_size = flash_size
        args.no_stub = False
        
        print('\nWriting firmware to flash...')
        write_flash(esp, args)
        print("\nFirmware write complete!")
        
    except FatalError as e:
        print(f'Failed to write flash: {e}')
    except FileNotFoundError:
        print(f'Firmware file not found: {firmware_path}')

