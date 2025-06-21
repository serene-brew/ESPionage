import struct
import re
import argparse
import sys
from typing import Dict, List, Optional

class ESP32FirmwareParser:
    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path
        with open(firmware_path, 'rb') as f:
            self.firmware_data = f.read()
        self.firmware_size = len(self.firmware_data)
    
    def parse_esp32_header(self) -> Dict:
        """Parse ESP32 firmware header"""
        if len(self.firmware_data) < 24:
            return {"error": "Firmware too small to contain a valid ESP32 header"}
        
        # ESP32 header format: magic(1) + segments(1) + flash_mode(1) + flash_size_freq(1) + entry_point(4)
        header = self.firmware_data[:8]
        magic = header[0]
        segment_count = header[1]
        flash_mode = header[2]
        flash_size_freq = header[3]
        entry_point = struct.unpack('<I', header[4:8])[0]
        
        # Extended header information
        extended_header = {}
        if len(self.firmware_data) >= 32:
            try:
                wp_pin, clk_drv, q_drv, d_drv, cs_drv, hd_drv, wp_drv = struct.unpack('<BBBBBBB', self.firmware_data[8:15])
                chip_id, min_chip_rev = struct.unpack('<HB', self.firmware_data[15:18])
                reserved = self.firmware_data[18:24]
                hash_appended = self.firmware_data[24]
                
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
        
        header_info = {
            'magic': f"0x{magic:02X}",
            'valid_magic': magic == 0xE9,
            'segment_count': segment_count,
            'flash_mode': self._decode_flash_mode(flash_mode),
            'flash_size': self._decode_flash_size(flash_size_freq & 0x0F),
            'flash_freq': self._decode_flash_freq((flash_size_freq >> 4) & 0x0F),
            'entry_point': f"0x{entry_point:08X}",
            'entry_point_region': self._identify_esp32_memory_region(entry_point)
        }
        
        if extended_header:
            header_info['extended'] = extended_header
        
        return header_info
    
    def _decode_flash_mode(self, mode: int) -> str:
        modes = {0: 'QIO', 1: 'QOUT', 2: 'DIO', 3: 'DOUT'}
        return modes.get(mode, f'Unknown ({mode})')
    
    def _decode_flash_size(self, size: int) -> str:
        sizes = {0: '1MB', 1: '2MB', 2: '4MB', 3: '8MB', 4: '16MB', 5: '32MB', 6: '64MB', 7: '128MB'}
        return sizes.get(size, f'Unknown ({size})')
    
    def _decode_flash_freq(self, freq: int) -> str:
        freqs = {0: '40MHz', 1: '26MHz', 2: '20MHz', 0xF: '80MHz'}
        return freqs.get(freq, f'Unknown ({freq})')
    
    def _identify_esp32_memory_region(self, address: int) -> str:
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
    
    def parse_esp32_partition_table(self, offset: int = 0x8000) -> Dict:
        """Parse ESP32 partition table using corrected logic from parser.py"""
        partition_info = {
            "found": False,
            "table_offset": f"0x{offset:08X}",
            "partitions": [],
            "format": None
        }
        
        # Try standard ESP32 partition table offsets
        standard_offsets = [0x8000, 0x9000, 0x10000, 0xd000, 0xe000]
        
        for test_offset in standard_offsets:
            if test_offset + 32 > len(self.firmware_data):
                continue
                
            if self._looks_like_partition_table(test_offset):
                offset = test_offset
                partition_info["table_offset"] = f"0x{offset:08X}"
                break
        else:
            # If no standard offset works, search through the firmware
            found_offset = self._search_partition_table()
            if found_offset:
                offset = found_offset
                partition_info["table_offset"] = f"0x{offset:08X}"
            else:
                return partition_info
        
        # Parse partition entries
        partitions = self._parse_partition_entries(offset)
        if partitions:
            partition_info["found"] = True
            partition_info["partitions"] = partitions
            partition_info["format"] = "ESP32 Standard"
        
        return partition_info
    
    def _looks_like_partition_table(self, offset: int) -> bool:
        """Check if data at offset looks like a partition table using parser.py logic"""
        if offset + 64 > len(self.firmware_data):
            return False
            
        data_at_offset = self.firmware_data[offset:offset+64]
        
        # Check for ESP32 partition table magic bytes
        magic_bytes = [0xAA, 0x50, 0xEB, 0xE9]
        if data_at_offset[0] not in magic_bytes and data_at_offset[1] not in magic_bytes:
            return False
        
        # Count valid partition entries
        entry_count = 0
        for i in range(0, min(256, len(self.firmware_data) - offset), 32):
            if offset + i + 32 > len(self.firmware_data):
                break
            entry = self.firmware_data[offset + i:offset + i + 32]
            if self._looks_like_partition_entry(entry):
                entry_count += 1
            elif entry_count > 0:  # Found some entries, then invalid - probably end
                break
        
        return entry_count >= 1  # At least one valid entry
    
    def _looks_like_partition_entry(self, entry: bytes) -> bool:
        """Check if entry looks like a valid partition entry using parser.py logic"""
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
    
    def _search_partition_table(self) -> Optional[int]:
        """Search for partition table in firmware if not found at standard offsets"""
        # Search every 4KB boundary
        for offset in range(0, len(self.firmware_data) - 64, 0x1000):
            if self._looks_like_partition_table(offset):
                return offset
        return None
    
    def _parse_partition_entries(self, table_offset: int) -> List[Dict]:
        """Parse partition entries from table"""
        partitions = []
        offset = table_offset
        
        for i in range(32):  # Max 32 partitions
            if offset + 32 > len(self.firmware_data):
                break
            
            entry = self.firmware_data[offset:offset+32]
            
            # Check for end of table
            if all(b == 0xFF for b in entry):
                break
            
            # Parse partition entry
            partition = self._parse_single_partition_entry(entry, offset)
            if partition:
                partitions.append(partition)
            elif i == 0:
                # First entry invalid, might not be partition table
                break
            
            offset += 32
        
        return partitions
    
    def _parse_single_partition_entry(self, entry: bytes, entry_offset: int) -> Optional[Dict]:
        """Parse a single partition entry"""
        if not self._looks_like_partition_entry(entry):
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
            type_name = self._decode_partition_type(type_val)
            subtype_name = self._decode_partition_subtype(type_val, subtype)
            
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
    
    def _decode_partition_type(self, type_val: int) -> str:
        types = {0x00: "App", 0x01: "Data"}
        return types.get(type_val, "Unknown")
    
    def _decode_partition_subtype(self, type_val: int, subtype: int) -> str:
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
    
    def extract_export_tables(self) -> Dict:
        """Extract export tables and function symbols from ESP32 firmware"""
        exports = {
            "found": False,
            "symbols": [],
            "export_sections": []
        }
        
        # Search for ESP32 API symbols
        esp32_symbols = self._find_esp32_symbols()
        if esp32_symbols:
            exports["symbols"] = esp32_symbols
            exports["found"] = True
        
        # Look for export table structures
        export_sections = self._find_export_sections()
        if export_sections:
            exports["export_sections"] = export_sections
            exports["found"] = True
        
        return exports
    
    def _find_esp32_symbols(self) -> List[Dict]:
        """Find ESP32 API symbols and function names"""
        symbols = []
        
        # Common ESP32 IDF function patterns
        patterns = [
            # WiFi functions
            rb'esp_wifi_init', rb'esp_wifi_start', rb'esp_wifi_stop',
            rb'esp_wifi_connect', rb'esp_wifi_disconnect', rb'esp_wifi_scan_start',
            
            # NVS functions
            rb'nvs_flash_init', rb'nvs_open', rb'nvs_close', rb'nvs_get_str',
            rb'nvs_set_str', rb'nvs_commit',
            
            # GPIO functions
            rb'gpio_config', rb'gpio_set_level', rb'gpio_get_level',
            
            # System functions
            rb'esp_restart', rb'esp_deep_sleep_start', rb'xTaskCreate',
            rb'vTaskDelay', rb'vTaskDelete'
        ]
        
        for pattern in patterns:
            matches = []
            start = 0
            while True:
                pos = self.firmware_data.find(pattern, start)
                if pos == -1:
                    break
                matches.append(pos)
                start = pos + 1
            
            if matches:
                symbols.append({
                    'name': pattern.decode('ascii'),
                    'occurrences': len(matches),
                    'offsets': [f"0x{offset:08X}" for offset in matches[:5]]
                })
        
        return symbols
    
    def _find_export_sections(self) -> List[Dict]:
        """Find potential export table sections"""
        sections = []
        
        # Search for repeated 4-byte patterns that could be function pointers
        for i in range(0, len(self.firmware_data) - 64, 4):
            potential_table = []
            for j in range(0, 64, 4):
                if i + j + 4 > len(self.firmware_data):
                    break
                
                value = struct.unpack('<I', self.firmware_data[i+j:i+j+4])[0]
                
                # Check if value looks like a valid ESP32 address
                if (0x40000000 <= value <= 0x50000000 or
                    0x3F000000 <= value <= 0x3FFFFFFF):
                    potential_table.append({
                        'offset': f"0x{i+j:08X}",
                        'address': f"0x{value:08X}",
                        'region': self._identify_esp32_memory_region(value)
                    })
                else:
                    break
            
            # If we found a reasonable number of consecutive function pointers
            if len(potential_table) >= 8:
                sections.append({
                    'table_offset': f"0x{i:08X}",
                    'entry_count': len(potential_table),
                    'entries': potential_table
                })
                
                # Skip ahead to avoid overlapping detections
                i += len(potential_table) * 4
        
        return sections[:10]  # Limit to first 10 potential tables
    
    def extract_strings(self, min_length: int = 4, max_length: int = 200) -> List[str]:
        """Extract readable ASCII strings from firmware"""
        strings = []
        current_string = ""
        
        for byte in self.firmware_data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
                if len(current_string) > max_length:
                    current_string = current_string[-max_length:]
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return list(set(strings))  # Remove duplicates
    
    def analyze_strings(self, strings: List[str]) -> Dict:
        """Analyze extracted strings for interesting patterns and return structured data"""
        analysis = {
            "wifi_related": [],
            "urls_endpoints": [],
            "version_info": [],
            "device_info": [],
            "certificates": [],
            "file_paths": [],
            "esp32_functions": [],
            "config_keys": [],
            "debug_messages": [],
            "urls": [],
            "files": []
        }
        
        for string in strings:
            string_lower = string.lower()
            
            # WiFi related strings
            if any(keyword in string_lower for keyword in ['wifi', 'ssid', 'password', 'wpa', 'wep', 'ap_', 'sta_']):
                analysis["wifi_related"].append(string)
            
            # URLs - only strings with protocol separators
            elif '://' in string:
                analysis["urls"].append(string)
            
            # Files - file paths and extensions
            elif (('/' in string and '.' in string) or 
                  string.endswith(('.bin', '.txt', '.json', '.cfg', '.conf', '.py', '.c', '.h'))):
                analysis["files"].append(string)
            
            # Version information
            if any(keyword in string_lower for keyword in ['version', 'ver', 'build', 'revision', 'v1.', 'v2.', 'v3.', 'v4.']):
                analysis["version_info"].append(string)
            
            # Device information
            if any(keyword in string_lower for keyword in ['esp32', 'device', 'serial', 'mac', 'chip', 'board']):
                analysis["device_info"].append(string)
            
            # Certificates
            if '-----BEGIN' in string or '-----END' in string or 'CERTIFICATE' in string:
                analysis["certificates"].append(string)
            
            # ESP32 function names
            if any(func in string for func in ['esp_', 'nvs_', 'gpio_', 'uart_', 'spi_', 'i2c_', 'timer_', 'task_']):
                analysis["esp32_functions"].append(string)
            
            # Configuration keys
            if any(keyword in string_lower for keyword in ['config', 'setting', 'param', 'key', 'value', 'enable', 'disable']):
                analysis["config_keys"].append(string)
            
            # Debug messages
            if any(keyword in string_lower for keyword in ['error', 'warning', 'debug', 'info', 'log', 'fail', 'success']):
                analysis["debug_messages"].append(string)
        
        # Remove duplicates but keep all items for parent project use
        for key in analysis:
            analysis[key] = list(set(analysis[key]))
        
        return analysis
    
    def get_analysis_results(self) -> Dict:
        # Extract all data
        strings = self.extract_strings()
        string_analysis = self.analyze_strings(strings)
        header = self.parse_esp32_header()
        partitions = self.parse_esp32_partition_table()
        symbols = self.extract_export_tables()
        
        # Structure data for easy parent project consumption
        results = {
            "firmware_info": {
                "path": self.firmware_path,
                "size_bytes": self.firmware_size,
                "size_mb": round(self.firmware_size / (1024*1024), 2),
                "size_kb": round(self.firmware_size / 1024, 1)
            },
            "header": {
                "raw": header,
                "is_valid": header.get('valid_magic', False),
                "magic": header.get('magic', ''),
                "entry_point": header.get('entry_point', ''),
                "flash_size": header.get('flash_size', ''),
                "flash_mode": header.get('flash_mode', '')
            },
            "partitions": {
                "found": partitions.get('found', False),
                "count": len(partitions.get('partitions', [])),
                "table_offset": partitions.get('table_offset', ''),
                "partitions_list": partitions.get('partitions', [])
            },
            "symbols": {
                "found": symbols.get('found', False),
                "count": len(symbols.get('symbols', [])),
                "symbols_list": symbols.get('symbols', [])
            },
            "urls": {
                "count": len(string_analysis.get('urls', [])),
                "urls_list": string_analysis.get('urls', [])
            },
            "files": {
                "count": len(string_analysis.get('files', [])),
                "files_list": string_analysis.get('files', [])
            },
            "strings": {
                "total_count": len(strings),
                "categories": {k: v for k, v in string_analysis.items() if k not in ['urls', 'files']},
                "category_counts": {k: len(v) for k, v in string_analysis.items() if k not in ['urls', 'files']}
            }
        }
        
        return results

def print_esp32_analysis(parser: ESP32FirmwareParser):
    print("=" * 80)
    print("ESP32 FIRMWARE ANALYSIS")
    print("=" * 80)
    
    # Firmware info
    print(f"\nFIRMWARE INFO:")
    print(f"  File: {parser.firmware_path}")
    print(f"  Size: {parser.firmware_size:,} bytes ({parser.firmware_size/1024:.1f} KB)")
    
    # Header analysis
    print(f"\nHEADER ANALYSIS:")
    print("-" * 40)
    header = parser.parse_esp32_header()
    
    if 'error' in header:
        print(f"  Error: {header['error']}")
    else:
        print(f"  Magic Number: {header['magic']} ({'Valid ESP32' if header['valid_magic'] else 'Invalid'})")
        print(f"  Segment Count: {header['segment_count']}")
        print(f"  Flash Mode: {header['flash_mode']}")
        print(f"  Flash Size: {header['flash_size']}")
        print(f"  Flash Frequency: {header['flash_freq']}")
        print(f"  Entry Point: {header['entry_point']} ({header['entry_point_region']})")
        
        if 'extended' in header:
            ext = header['extended']
            print(f"  Chip ID: {ext['chip_id']}")
            print(f"  Min Chip Revision: {ext['min_chip_rev']}")
            print(f"  Hash Appended: {ext['hash_appended']}")
    
    # Partition table
    print(f"\nPARTITION TABLE:")
    print("-" * 40)
    partitions = parser.parse_esp32_partition_table()
    
    if partitions['found']:
        print(f"  Table Offset: {partitions['table_offset']}")
        print(f"  Partitions Found: {len(partitions['partitions'])}")
        print()
        
        for i, part in enumerate(partitions['partitions']):
            print(f"  Partition {i+1}:")
            print(f"    Label: {part['label']}")
            print(f"    Type: {part['type']}")
            print(f"    Subtype: {part['subtype']}")
            print(f"    Offset: {part['offset']}")
            print(f"    Size: {part['size_mb']}")
            print(f"    Encrypted: {'Yes' if part['encrypted'] else 'No'}")
            print()
    else:
        print("  No valid partition table found")
    
    # Export tables
    print(f"\nSYMBOLS:")
    print("-" * 40)
    exports = parser.extract_export_tables()
    
    if exports['found']:
        if exports['symbols']:
            print(f"  ESP32 API Symbols Found: {len(exports['symbols'])}")
            print()
            for symbol in exports['symbols'][:10]:
                print(f"    {symbol['name']}:")
                print(f"      Occurrences: {symbol['occurrences']}")
                print(f"      Offsets: {', '.join(symbol['offsets'])}")
                print()
        
        # if exports['export_sections']:
        #     print(f"  Potential Export Tables: {len(exports['export_sections'])}")
        #     print()
        #     for i, section in enumerate(exports['export_sections'][:3]):
        #         print(f"    Table {i+1}:")
        #         print(f"      Offset: {section['table_offset']}")
        #         print(f"      Entries: {section['entry_count']}")
        #         print(f"      Sample entries:")
        #         for entry in section['entries'][:3]:
        #             print(f"        {entry['offset']}: {entry['address']} ({entry['region']})")
        #         print()
    else:
        print("  No export tables or symbols found")
    
    # String Analysis
    print(f"\nSTRING ANALYSIS:")
    print("-" * 40)
    
    # Extract and analyze strings
    strings = parser.extract_strings()
    string_analysis = parser.analyze_strings(strings)
    
    print(f"  Total Strings Found: {len(strings)}")
    print()
    
    # Print categorized strings
    category_names = {
        "wifi_related": "WiFi Related",
        "urls_endpoints": "URLs/Endpoints", 
        "version_info": "Version Info",
        "device_info": "Device Info",
        "esp32_functions": "ESP32 Functions",
        "config_keys": "Configuration Keys",
        "debug_messages": "Debug Messages",
        "certificates": "Certificates",
        "file_paths": "File Paths",
        "urls": "URLs",
        "files": "Files"
    }
    
    for key, items in string_analysis.items():
        if items:
            display_name = category_names.get(key, key.replace('_', ' ').title())
            print(f"  {display_name} ({len(items)}):")
            for item in items:  # Show all items
                print(f"    - {item[:80]}{'...' if len(item) > 80 else ''}")
            print()
    
    print("=" * 80)

# def main():
#     parser = argparse.ArgumentParser(description="ESP32 Firmware Parser - Headers, Partitions & Exports")
#     parser.add_argument("firmware", help="Path to ESP32 firmware binary file")
    
#     args = parser.parse_args()
    
#     try:
#         esp32_parser = ESP32FirmwareParser(args.firmware)
        
#         # Get structured results for parent project
#         results = esp32_parser.get_analysis_results()
        
#         # Print for testing (this will be removed when used in parent project)
#         print_esp32_analysis(esp32_parser)
        
#         # Optional: Save results to JSON for parent project
#         import json
#         output_file = args.firmware + "_analysis.json"
#         with open(output_file, 'w') as f:
#             json.dump(results, f, indent=2)
#         print(f"\n[INFO] Structured results saved to: {output_file}")
        
#     except FileNotFoundError:
#         print(f"Error: Firmware file '{args.firmware}' not found")
#         sys.exit(1)
#     except Exception as e:
#         print(f"Error analyzing firmware: {e}")
#         sys.exit(1)

# if __name__ == "__main__":
#     main()
