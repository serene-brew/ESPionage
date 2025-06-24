"""
Author: Imon Chakraborty (RiserSama)
ESP Partition Table Parser

This module provides functionality to parse and analyze ESP32 and ESP8266 firmware partition tables.
It can automatically detect partition table locations, parse partition entries, decode partition
types and subtypes, and format analysis results with colored terminal output.

The parser supports the standard ESP partition table format and can handle various partition
types including app partitions (factory, OTA), data partitions (NVS, SPIFFS, FAT, etc.),
and custom partition types. It validates partition entries and provides detailed information
about each partition including size, offset, encryption status, and flags.

Main features:
- Automatic partition table location detection
- Partition entry validation and parsing
- Support for standard ESP partition types and subtypes
- Encryption flag detection
- Memory layout analysis
- Colored terminal output formatting
"""

import struct
from typing import Dict, List, Optional, Tuple
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
    
    @args: firmware_data (bytes): Raw firmware binary data
        
    @return: Tuple[ChipType, int]: A tuple containing the detected chip type and base address
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

def parse_esp_partition_table(firmware_path: str) -> Tuple[str, int]:
    """
    Parse ESP firmware partition table and return formatted analysis results.
    
    Reads and analyzes an ESP firmware file to locate and parse the partition table.
    Attempts to find the partition table at standard offsets or by searching through
    the firmware. Returns detailed information about all partitions found.
    
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
        
        # Detect chip type and base address
        chip_type, base_address = detect_chip_type_with_base(firmware_data)
        
        partition_info = {
            "found": False,
            "table_offset": "0x8000",
            "partitions": [],
            "format": None,
            "chip_type": chip_type.value,
            "base_address": base_address
        }
        
        # Try standard ESP partition table offsets
        standard_offsets = [0x8000, 0x9000, 0x10000, 0xd000, 0xe000]
        offset = 0x8000
        
        for test_offset in standard_offsets:
            if test_offset + 32 > len(firmware_data):
                continue
                
            if _looks_like_partition_table(firmware_data, test_offset):
                offset = test_offset
                partition_info["table_offset"] = f"0x{offset:08X}"
                break
        else:
            # If no standard offset works, search through the firmware
            found_offset = _search_partition_table(firmware_data)
            if found_offset:
                offset = found_offset
                partition_info["table_offset"] = f"0x{offset:08X}"
            else:
                status = 0
                return "", status
        
        # Parse partition entries
        partitions = _parse_partition_entries(firmware_data, offset)
        if partitions:
            partition_info["found"] = True
            partition_info["partitions"] = partitions
            partition_info["format"] = "ESP Standard"
        
        return _format_partition_output(partition_info)
        
    except Exception as e:
        status = 0
        return f"Error parsing ESP partition table: {str(e)}", status

def _looks_like_partition_table(firmware_data: bytes, offset: int) -> bool:
    """
    Check if data at given offset looks like a valid partition table.
    
    Validates potential partition table by checking for magic bytes and
    counting valid partition entries. Uses heuristics to determine if
    the data structure matches ESP partition table format.
    
    Args:
        firmware_data (bytes): Raw firmware binary data
        offset (int): Offset to check for partition table
        
    Returns:
        bool: True if data appears to be a valid partition table
    """
    if offset + 64 > len(firmware_data):
        return False
        
    data_at_offset = firmware_data[offset:offset+64]
    
    # Check for ESP partition table magic bytes
    magic_bytes = [0xAA, 0x50, 0xEB, 0xE9]
    if data_at_offset[0] not in magic_bytes and data_at_offset[1] not in magic_bytes:
        return False
    
    # Count valid partition entries
    entry_count = 0
    for i in range(0, min(256, len(firmware_data) - offset), 32):
        if offset + i + 32 > len(firmware_data):
            break
        entry = firmware_data[offset + i:offset + i + 32]
        if _looks_like_partition_entry(entry):
            entry_count += 1
        elif entry_count > 0:  # Found some entries, then invalid - probably end
            break
    
    return entry_count >= 1  # At least one valid entry

def _looks_like_partition_entry(entry: bytes) -> bool:
    """
    Validate if a 32-byte entry looks like a valid partition entry.
    
    Performs various checks on partition entry structure including field
    validation, alignment checks, size validation, and label content
    verification to determine if the entry is valid.
    
    Args:
        entry (bytes): 32-byte partition entry data
        
    Returns:
        bool: True if entry appears to be a valid partition entry
    """
    if len(entry) != 32:
        return False
    
    # Check if all 0xFF (end of table marker)
    if all(b == 0xFF for b in entry):
        return False
    
    try:
        # Parse basic fields  
        type_val = entry[2] if len(entry) > 2 else 0
        subtype = entry[3] if len(entry) > 3 else 0
        
        if len(entry) >= 12:
            part_offset = struct.unpack('<I', entry[4:8])[0]
            size = struct.unpack('<I', entry[8:12])[0]
            
            # Validate offset alignment (should be 4KB aligned for most partitions)
            if part_offset != 0 and part_offset % 0x1000 != 0:
                return False
            
            # Validate size (shouldn't be unreasonably large)
            if size > 0x1000000:  # > 16MB
                return False
            
            # Check label area for reasonable content
            if len(entry) >= 28:
                label = entry[12:28]
                # At least half should be printable ASCII or null
                printable_chars = sum(1 for b in label if 32 <= b <= 126 or b == 0)
                if printable_chars < len(label) // 2:
                    return False
        
        # Check for valid type values (ESP partition types)
        if type_val in [0x00, 0x01] and subtype < 0x80:
            return True
            
    except (struct.error, IndexError):
        return False
    
    return False

def _search_partition_table(firmware_data: bytes) -> Optional[int]:
    """
    Search for partition table throughout the firmware at 4KB boundaries.
    
    Scans the entire firmware file at 4KB intervals looking for what
    appears to be a valid partition table when standard offsets fail.
    
    Args:
        firmware_data (bytes): Raw firmware binary data
        
    Returns:
        Optional[int]: Offset of partition table if found, None otherwise
    """
    # Search every 4KB boundary
    for offset in range(0, len(firmware_data) - 64, 0x1000):
        if _looks_like_partition_table(firmware_data, offset):
            return offset
    return None

def _parse_partition_entries(firmware_data: bytes, table_offset: int) -> List[Dict]:
    """
    Parse partition entries from table starting at given offset.
    
    Reads sequential 32-byte partition entries from the table until
    an end marker (all 0xFF) is found or maximum partition count is reached.
    
    Args:
        firmware_data (bytes): Raw firmware binary data
        table_offset (int): Starting offset of partition table
        
    Returns:
        List[Dict]: List of parsed partition entry dictionaries
    """
    partitions = []
    offset = table_offset
    
    for i in range(32):  # Max 32 partitions
        if offset + 32 > len(firmware_data):
            break
        
        entry = firmware_data[offset:offset+32]
        
        # Check for end of table
        if all(b == 0xFF for b in entry):
            break
        
        # Parse partition entry
        partition = _parse_single_partition_entry(entry, offset)
        if partition:
            partitions.append(partition)
        elif i == 0:
            # First entry invalid, might not be partition table
            break
        
        offset += 32
    
    return partitions

def _parse_single_partition_entry(entry: bytes, entry_offset: int) -> Optional[Dict]:
    """
    Parse a single 32-byte partition entry into structured data.
    
    Extracts and decodes all fields from a partition entry including magic number,
    type, subtype, offset, size, label, flags, and encryption status.
    
    Args:
        entry (bytes): 32-byte partition entry data
        entry_offset (int): Offset of this entry in the firmware
        
    Returns:
        Optional[Dict]: Parsed partition data or None if invalid
    """
    if not _looks_like_partition_entry(entry):
        return None
    
    try:
        magic = struct.unpack('<H', entry[0:2])[0]
        type_val = entry[2]
        subtype = entry[3]
        part_offset = struct.unpack('<I', entry[4:8])[0]
        size = struct.unpack('<I', entry[8:12])[0]
        
        label_bytes = entry[12:28]
        label = label_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
        
        flags = struct.unpack('<I', entry[28:32])[0] if len(entry) >= 32 else 0
        
        # Decode partition types
        type_name = _decode_partition_type(type_val)
        subtype_name = _decode_partition_subtype(type_val, subtype)
        
        return {
            'entry_offset': f"0x{entry_offset:08X}",
            'magic': f"0x{magic:04X}",
            'type': f"{type_name} (0x{type_val:02X})",
            'subtype': f"{subtype_name} (0x{subtype:02X})",
            'offset': f"0x{part_offset:08X}",
            'size': f"0x{size:08X}",
            'size_mb': f"{size / (1024*1024):.2f} MB" if size >= 1024*1024 else f"{size / 1024:.1f} KB",
            'label': label if label else "unnamed",
            'flags': f"0x{flags:08X}",
            'encrypted': bool(flags & 0x01),
            'end_offset': f"0x{part_offset + size:08X}"
        }
        
    except (struct.error, IndexError):
        return None

def _decode_partition_type(type_val: int) -> str:
    """
    Decode partition type value to human-readable string.
    
    Converts numeric partition type (0x00 = App, 0x01 = Data) to
    descriptive string representation.
    
    Args:
        type_val (int): Partition type value from entry
        
    Returns:
        str: Human-readable partition type description
    """
    types = {0x00: "App", 0x01: "Data"}
    return types.get(type_val, "Unknown")

def _decode_partition_subtype(type_val: int, subtype: int) -> str:
    """
    Decode partition subtype value to human-readable string.
    
    Converts numeric partition subtype based on the partition type.
    App partitions include Factory, OTA_0-15, Test. Data partitions
    include NVS, SPIFFS, FAT, PHY, etc.
    
    Args:
        type_val (int): Partition type value (determines subtype interpretation)
        subtype (int): Partition subtype value from entry
        
    Returns:
        str: Human-readable partition subtype description
    """
    if type_val == 0x00:  # App
        subtypes = {
            0x00: "Factory", 0x10: "OTA_0", 0x11: "OTA_1", 0x12: "OTA_2",
            0x13: "OTA_3", 0x14: "OTA_4", 0x15: "OTA_5", 0x16: "OTA_6",
            0x17: "OTA_7", 0x18: "OTA_8", 0x19: "OTA_9", 0x1A: "OTA_10",
            0x1B: "OTA_11", 0x1C: "OTA_12", 0x1D: "OTA_13", 0x1E: "OTA_14",
            0x1F: "OTA_15", 0x20: "Test"
        }
    elif type_val == 0x01:  # Data
        subtypes = {
            0x00: "OTA", 0x01: "PHY", 0x02: "NVS", 0x03: "CoreDump",
            0x04: "NVS_KEYS", 0x05: "EFUSE_EM", 0x06: "Undefined",
            0x80: "ESPHTTPD", 0x81: "FAT", 0x82: "SPIFFS", 0x83: "LittleFS"
        }
    else:
        subtypes = {}
    
    return subtypes.get(subtype, "Unknown")

def _format_partition_output(partition_info: Dict) -> Tuple[str, int]:
    """
    Format partition table analysis results for terminal display.
    
    Creates formatted output with ANSI color codes showing partition table
    information, individual partition details, and analysis summary.
    
    Args:
        partition_info (Dict): Dictionary containing parsed partition data
        
    Returns:
        Tuple[str, int]: A tuple containing:
            - str: Formatted output string with ANSI colors
            - int: Status code (1 for success, 0 for failure)
    """
    status = 1
    output = []
    output.append("\033[38;5;169m==============================================================================================\033[0m")
    output.append(f"\033[38;5;72mAnalyzing firmware: {len(partition_info['partitions'])} partitions ({partition_info.get('chip_type', 'ESP').upper()})")
    output.append(f"Base address: 0x{partition_info.get('base_address', 0x40000000):08X}\033[0m")
    output.append("")
    
    if not partition_info["found"]:
        status = 0
        return "", status
    output.append("")
    
    output.append("\033[38;5;220mPARTITION TABLE INFO:\033[0m")
    output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
    output.append(f"\033[38;5;219mTable Offset:\033[0m {partition_info['table_offset']}")
    output.append(f"\033[38;5;219mPartitions Found:\033[0m {len(partition_info['partitions'])}")
    output.append(f"\033[38;5;219mFormat:\033[0m {partition_info['format']}\033[0m")
    output.append("")
    
    for i, part in enumerate(partition_info['partitions']):
        output.append(f"\033[38;5;220mPARTITION #{i+1}:\033[0m")
        output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
        output.append(f"\033[38;5;219mLabel:\033[0m          {part['label']}")
        output.append(f"\033[38;5;219mType:\033[0m           {part['type']}")
        output.append(f"\033[38;5;219mSubtype:\033[0m        {part['subtype']}")
        output.append(f"\033[38;5;219mOffset:\033[0m         {part['offset']}")
        output.append(f"\033[38;5;219mSize:\033[0m           {part['size_mb']}")
        output.append(f"\033[38;5;219mEnd Offset:\033[0m     {part['end_offset']}")
        output.append(f"\033[38;5;219mEncrypted:\033[0m      {'Yes' if part['encrypted'] else 'No'}")
        output.append(f"\033[38;5;219mFlags:\033[0m          {part['flags']}\033[0m")
        output.append("")
    
    return "\n".join(output), status