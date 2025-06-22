import struct
from typing import Dict, List, Optional, Tuple

def parse_esp32_partition_table(firmware_path: str) -> Tuple[str, int]:
    status = 1
    try:
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        partition_info = {
            "found": False,
            "table_offset": "0x8000",
            "partitions": [],
            "format": None
        }
        
        # Try standard ESP32 partition table offsets
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
    if offset + 64 > len(firmware_data):
        return False
        
    data_at_offset = firmware_data[offset:offset+64]
    
    # Check for ESP32 partition table magic bytes
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
        
        # Check for valid type values (ESP32 partition types)
        if type_val in [0x00, 0x01] and subtype < 0x80:
            return True
            
    except (struct.error, IndexError):
        return False
    
    return False

def _search_partition_table(firmware_data: bytes) -> Optional[int]:
    # Search every 4KB boundary
    for offset in range(0, len(firmware_data) - 64, 0x1000):
        if _looks_like_partition_table(firmware_data, offset):
            return offset
    return None

def _parse_partition_entries(firmware_data: bytes, table_offset: int) -> List[Dict]:
    """Parse partition entries from table"""
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
    types = {0x00: "App", 0x01: "Data"}
    return types.get(type_val, "Unknown")

def _decode_partition_subtype(type_val: int, subtype: int) -> str:
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
    status = 1
    output = []
    output.append("=" * 60)
    output.append("ESP PARTITION TABLE ANALYSIS")
    output.append("=" * 60)
    output.append("")
    
    if not partition_info["found"]:
        status = 0
        return "", status
    
    output.append(f"Table Offset: {partition_info['table_offset']}")
    output.append(f"Partitions Found: {len(partition_info['partitions'])}")
    output.append(f"Format: {partition_info['format']}")
    output.append("")
    
    for i, part in enumerate(partition_info['partitions']):
        output.append(f"PARTITION {i+1}:")
        output.append("-" * 30)
        output.append(f"Label:          {part['label']}")
        output.append(f"Type:           {part['type']}")
        output.append(f"Subtype:        {part['subtype']}")
        output.append(f"Offset:         {part['offset']}")
        output.append(f"Size:           {part['size_mb']}")
        output.append(f"End Offset:     {part['end_offset']}")
        output.append(f"Encrypted:      {'Yes' if part['encrypted'] else 'No'}")
        output.append(f"Flags:          {part['flags']}")
        output.append("")
    
    return "\n".join(output), status