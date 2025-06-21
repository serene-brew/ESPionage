import struct
from typing import Dict, Optional

def parse_esp32_header(firmware_path: str) -> str:
    try:
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        if len(firmware_data) < 24:
            return "Error: Firmware too small to contain a valid ESP32 header"
        
        # ESP32 header format: magic(1) + segments(1) + flash_mode(1) + flash_size_freq(1) + entry_point(4)
        header = firmware_data[:8]
        magic = header[0]
        segment_count = header[1]
        flash_mode = header[2]
        flash_size_freq = header[3]
        entry_point = struct.unpack('<I', header[4:8])[0]
        
        # Extended header information
        extended_header = {}
        if len(firmware_data) >= 32:
            try:
                wp_pin, clk_drv, q_drv, d_drv, cs_drv, hd_drv, wp_drv = struct.unpack('<BBBBBBB', firmware_data[8:15])
                chip_id, min_chip_rev = struct.unpack('<HB', firmware_data[15:18])
                reserved = firmware_data[18:24]
                hash_appended = firmware_data[24]
                
                extended_header = {
                    'wp_pin': wp_pin,
                    'drive_settings': {
                        'clk_drv': clk_drv,
                        'q_drv': q_drv,
                        'd_drv': d_drv,
                        'cs_drv': cs_drv,
                        'hd_drv': hd_drv,
                        'wp_drv': wp_drv
                    },
                    'chip_id': f"0x{chip_id:04X}",
                    'min_chip_rev': min_chip_rev,
                    'hash_appended': hash_appended
                }
            except:
                pass
        
        # Format output
        output = []
        output.append("=" * 60)
        output.append("ESP FIRMWARE HEADER ANALYSIS")
        output.append("=" * 60)
        output.append("")
        
        # Basic header info
        output.append("BASIC HEADER:")
        output.append("-" * 30)
        output.append(f"Magic Number:     0x{magic:02X} ({'Valid' if magic == 0xE9 else 'Invalid'})")
        output.append(f"Segment Count:    {segment_count}")
        output.append(f"Flash Mode:       {_decode_flash_mode(flash_mode)}")
        output.append(f"Flash Size:       {_decode_flash_size(flash_size_freq & 0x0F)}")
        output.append(f"Flash Frequency:  {_decode_flash_freq((flash_size_freq >> 4) & 0x0F)}")
        output.append(f"Entry Point:      0x{entry_point:08X}")
        output.append(f"Entry Region:     {_identify_esp32_memory_region(entry_point)}")
        output.append("")
        
        # Extended header info
        if extended_header:
            output.append("EXTENDED HEADER:")
            output.append("-" * 30)
            output.append(f"WP Pin:           {extended_header['wp_pin']}")
            output.append(f"Chip ID:          {extended_header['chip_id']}")
            output.append(f"Min Chip Rev:     {extended_header['min_chip_rev']}")
            output.append(f"Hash Appended:    {extended_header['hash_appended']}")
            output.append("")
            
            output.append("DRIVE SETTINGS:")
            output.append("-" * 30)
            drive = extended_header['drive_settings']
            output.append(f"CLK Drive:        {drive['clk_drv']}")
            output.append(f"Q Drive:          {drive['q_drv']}")
            output.append(f"D Drive:          {drive['d_drv']}")
            output.append(f"CS Drive:         {drive['cs_drv']}")
            output.append(f"HD Drive:         {drive['hd_drv']}")
            output.append(f"WP Drive:         {drive['wp_drv']}")
            output.append("")
        
        # Firmware info
        output.append("FIRMWARE INFO:")
        output.append("-" * 30)
        output.append(f"File Size:        {len(firmware_data):,} bytes ({len(firmware_data)/1024:.1f} KB)")
        output.append(f"Valid Header:     {'Yes' if magic == 0xE9 else 'No'}")
        
        return "\n".join(output)
        
    except Exception as e:
        return f"Error parsing ESP32 header: {str(e)}"

def _decode_flash_mode(mode: int) -> str:
    modes = {0: 'QIO', 1: 'QOUT', 2: 'DIO', 3: 'DOUT'}
    return modes.get(mode, f'Unknown ({mode})')

def _decode_flash_size(size: int) -> str:
    sizes = {0: '1MB', 1: '2MB', 2: '4MB', 3: '8MB', 4: '16MB', 5: '32MB', 6: '64MB', 7: '128MB'}
    return sizes.get(size, f'Unknown ({size})')

def _decode_flash_freq(freq: int) -> str:
    freqs = {0: '40MHz', 1: '26MHz', 2: '20MHz', 0xF: '80MHz'}
    return freqs.get(freq, f'Unknown ({freq})')

def _identify_esp32_memory_region(address: int) -> str:
    if 0x3F400000 <= address <= 0x3F800000:
        return "External Flash Memory"
    elif 0x3FF80000 <= address <= 0x3FFFFFFF:
        return "RTC FAST Memory"
    elif 0x50000000 <= address <= 0x50002000:
        return "RTC SLOW Memory"
    elif 0x40080000 <= address <= 0x400A0000:
        return "Internal ROM 1"
    elif 0x3FF90000 <= address <= 0x40000000:
        return "Internal SRAM 1"
    elif 0x3F800000 <= address <= 0x3FC00000:
        return "External SRAM"
    elif 0x400C0000 <= address <= 0x400C2000:
        return "RTC FAST Memory"
    elif 0x40070000 <= address <= 0x40080000:
        return "Internal ROM 0"
    elif 0x40020000 <= address <= 0x40070000:
        return "Internal SRAM 0"
    elif 0x40000000 <= address <= 0x40020000:
        return "Internal ROM"
    else:
        return f"Unknown Region (0x{address:08X})"