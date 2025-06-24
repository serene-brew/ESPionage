"""
Author: Imon Chakraborty (RiserSama)
ESP Firmware Header Parser

This module provides functionality to parse and analyze ESP32 and ESP8266 firmware headers.
It can detect chip types, extract header information, decode flash configurations,
and identify memory regions. The parser supports both basic and extended ESP firmware
header formats and provides colored terminal output for analysis results.

Main features:
- Automatic chip type detection (ESP32/ESP8266)
- Header validation and parsing
- Flash configuration decoding
- Memory region identification
- Extended header information extraction
"""

import struct
from typing import Dict, Optional, Tuple
from enum import Enum

class ChipType(Enum):
    ESP32 = "esp32"
    ESP8266 = "esp8266"
    UNKNOWN = "unknown"

def detect_chip_type_with_base(firmware_data: bytes) -> Tuple[ChipType, int]:
    """
    Enhanced chip detection that returns both chip type and base address.
    
    Analyzes firmware data to determine the ESP chip type using multiple heuristics
    including string analysis and size-based detection.
    
    Args:
        firmware_data (bytes): Raw firmware binary data
        
    Returns:
        Tuple[ChipType, int]: A tuple containing the detected chip type and base address
    """
    size = len(firmware_data)
    
    # Check for chip identification strings
    try:
        text = firmware_data.decode('ascii', errors='ignore').lower()
        if 'esp32' in text:
            return ChipType.ESP32, 0x40000000
        elif 'esp8266' in text or '8266' in text:
            return ChipType.ESP8266, 0x40000000
    except:
        pass
    
    # Size-based heuristics
    if size > 2 * 1024 * 1024:  # > 2MB typically ESP32
        return ChipType.ESP32, 0x40000000
    elif size < 1024 * 1024:  # < 1MB typically ESP8266
        return ChipType.ESP8266, 0x40000000
    
    # Default to ESP32 for medium sizes
    return ChipType.ESP32, 0x40000000

def detect_chip_type(firmware_data: bytes) -> ChipType:
    """
    Simple chip detection based on firmware characteristics.
    
    A convenience function that wraps detect_chip_type_with_base() and returns
    only the chip type without the base address.
    
    Args:
        firmware_data (bytes): Raw firmware binary data
        
    Returns:
        ChipType: The detected chip type (ESP32, ESP8266, or UNKNOWN)
    """
    chip_type, _ = detect_chip_type_with_base(firmware_data)
    return chip_type

def parse_esp_header(firmware_path: str) -> Tuple[str, int]:
    """
    Parse ESP firmware header and return formatted analysis results.
    
    Reads and analyzes an ESP firmware file, extracting header information including
    magic number, segment count, flash configuration, entry point, and extended
    header data if available. Returns a formatted string with colored output
    suitable for terminal display.
    
    Args:
        firmware_path (str): Path to the firmware file to analyze
        
    Returns:
        Tuple[str, int]: A tuple containing:
            - str: Formatted analysis output with ANSI color codes
            - int: Status code (1 for success, 0 for failure)
    """
    status = 1
    try:
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        if len(firmware_data) < 24:
            status = 0
            return "", status
        
        # Detect chip type and base address
        chip_type, base_address = detect_chip_type_with_base(firmware_data)
        
        # ESP header format: magic(1) + segments(1) + flash_mode(1) + flash_size_freq(1) + entry_point(4)
        header = firmware_data[:8]
        magic = header[0]
        segment_count = header[1]
        flash_mode = header[2]
        flash_size_freq = header[3]
        entry_point = struct.unpack('<I', header[4:8])[0]
        
        if magic != 0xE9:
            status = 0
            return "", status
        
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
        output.append("\033[38;5;169m==============================================================================================\033[0m")
        output.append(f"\033[38;5;72mAnalyzing firmware: {len(firmware_data)/1024:.1f} KB ({chip_type.value.upper()})")
        output.append(f"Base address: 0x{base_address:08X}\033[0m")
        output.append("")
        
        # Basic header info
        output.append("\033[38;5;220mBASIC HEADER:\033[0m")
        output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
        output.append(f"\033[38;5;219mMagic Number:\033[0m     0x{magic:02X} ({'Valid' if magic == 0xE9 else 'Invalid'})")
        output.append(f"\033[38;5;219mSegment Count:\033[0m    {segment_count}")
        output.append(f"\033[38;5;219mFlash Mode:\033[0m       {_decode_flash_mode(flash_mode)}")
        output.append(f"\033[38;5;219mFlash Size:\033[0m       {_decode_flash_size(flash_size_freq & 0x0F)}")
        output.append(f"\033[38;5;219mFlash Frequency:\033[0m  {_decode_flash_freq((flash_size_freq >> 4) & 0x0F)}")
        output.append(f"\033[38;5;219mEntry Point:\033[0m      0x{entry_point:08X}")
        output.append(f"\033[38;5;219mEntry Region:\033[0m     {_identify_esp_memory_region(entry_point)}\033[0m")
        output.append("")
        
        # Extended header info
        if extended_header:
            output.append("\033[38;5;220mEXTENDED HEADER:\033[0m")
            output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
            output.append(f"\033[38;5;219mWP Pin:\033[0m           {extended_header['wp_pin']}")
            output.append(f"\033[38;5;219mChip ID:\033[0m          {extended_header['chip_id']}")
            output.append(f"\033[38;5;219mMin Chip Rev:\033[0m     {extended_header['min_chip_rev']}")
            output.append(f"\033[38;5;219mHash Appended:\033[0m    {extended_header['hash_appended']}\033[0m")
            output.append("")
            
            output.append("\033[38;5;220mDRIVE SETTINGS:\033[0m")
            output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
            drive = extended_header['drive_settings']
            output.append(f"\033[38;5;219mCLK Drive:\033[0m        {drive['clk_drv']}")
            output.append(f"\033[38;5;219mQ Drive:\033[0m          {drive['q_drv']}")
            output.append(f"\033[38;5;219mD Drive:\033[0m          {drive['d_drv']}")
            output.append(f"\033[38;5;219mCS Drive:\033[0m         {drive['cs_drv']}")
            output.append(f"\033[38;5;219mHD Drive:\033[0m         {drive['hd_drv']}")
            output.append(f"\033[38;5;219mWP Drive:\033[0m         {drive['wp_drv']}\033[0m")
            output.append("")
        
        # Firmware info
        output.append("\033[38;5;220mFIRMWARE INFO:\033[0m")
        output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
        output.append(f"\033[38;5;219mDetected Chip:\033[0m    {chip_type.value.upper()}")
        output.append(f"\033[38;5;219mFile Size:\033[0m        {len(firmware_data):,} bytes ({len(firmware_data)/1024:.1f} KB)")
        output.append(f"\033[38;5;219mValid Header:\033[0m     {'Yes' if magic == 0xE9 else 'No'}\033[0m")
        
        return "\n".join(output), status
        
    except Exception as e:
        status = 0
        return f"Error parsing ESP header: {str(e)}", status

def _decode_flash_mode(mode: int) -> str:
    """
    Decode flash mode value to human-readable string.
    
    Converts the numeric flash mode value from the firmware header into
    a descriptive string (QIO, QOUT, DIO, DOUT).
    
    Args:
        mode (int): Flash mode value from firmware header
        
    Returns:
        str: Human-readable flash mode description
    """
    modes = {0: 'QIO', 1: 'QOUT', 2: 'DIO', 3: 'DOUT'}
    return modes.get(mode, f'Unknown ({mode})')

def _decode_flash_size(size: int) -> str:
    """
    Decode flash size value to human-readable string.
    
    Converts the numeric flash size value from the firmware header into
    a descriptive string with capacity (1MB, 2MB, 4MB, etc.).
    
    Args:
        size (int): Flash size value from firmware header
        
    Returns:
        str: Human-readable flash size description
    """
    sizes = {0: '1MB', 1: '2MB', 2: '4MB', 3: '8MB', 4: '16MB', 5: '32MB', 6: '64MB', 7: '128MB'}
    return sizes.get(size, f'Unknown ({size})')

def _decode_flash_freq(freq: int) -> str:
    """
    Decode flash frequency value to human-readable string.
    
    Converts the numeric flash frequency value from the firmware header into
    a descriptive string with frequency (40MHz, 26MHz, 20MHz, 80MHz).
    
    Args:
        freq (int): Flash frequency value from firmware header
        
    Returns:
        str: Human-readable flash frequency description
    """
    freqs = {0: '40MHz', 1: '26MHz', 2: '20MHz', 0xF: '80MHz'}
    return freqs.get(freq, f'Unknown ({freq})')

def _identify_esp_memory_region(address: int) -> str:
    """
    Identify the memory region for a given address.
    
    Maps memory addresses to their corresponding regions in ESP32/ESP8266
    memory layout (ROM, SRAM, Flash, RTC memory, etc.).
    
    Args:
        address (int): Memory address to identify
        
    Returns:
        str: Human-readable description of the memory region
    """
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