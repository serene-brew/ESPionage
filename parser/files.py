"""
Author: Imon Chakraborty (RiserSama)
ESP Firmware File Path Extractor

This module provides functionality to extract and analyze file paths from ESP32 and ESP8266 firmware.
It identifies strings that appear to be file paths by looking for common file extensions and
validating path structure. This helps security researchers and developers understand what files
might be embedded or referenced within the firmware.

The extractor focuses on finding references to configuration files, web assets, certificates,
source code files, and other embedded resources that could provide insights into the firmware's
functionality and potential attack vectors.

Main features:
- String extraction from firmware binaries
- File path identification based on extension patterns
- Path validation using heuristics
- Categorization by file type/extension
- Support for common embedded system file types
- Colored terminal output formatting
"""

from typing import List, Tuple
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

def extract_files_from_firmware(firmware_path: str) -> Tuple[str, int]:
    """
    Extract and analyze file paths from ESP firmware.
    
    Main entry point for file path extraction. Reads the firmware file,
    extracts strings, filters for file paths, and returns formatted
    analysis results suitable for terminal display.
    
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
        
        # Extract strings first
        strings = _extract_strings(firmware_data)
        
        # Filter for file paths
        files = _extract_files(strings)
        
        return _format_files_output(files, chip_type, base_address)
        
    except Exception as e:
        status = 0
        return f"Error extracting files: {str(e)}", status

def _extract_strings(firmware_data: bytes, min_length: int = 4, max_length: int = 200) -> List[str]:
    """
    Extract printable ASCII strings from firmware binary data.
    
    Scans through firmware bytes to identify sequences of printable ASCII characters
    that form strings. Filters strings by minimum and maximum length requirements
    and removes duplicates from the result set.
    
    Args:
        firmware_data (bytes): Raw firmware binary data to scan
        min_length (int, optional): Minimum string length to include. Defaults to 4.
        max_length (int, optional): Maximum string length to include. Defaults to 200.
        
    Returns:
        List[str]: List of unique strings found in the firmware
    """
    strings = []
    current_string = ""
    
    for byte in firmware_data:
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

def _extract_files(strings: List[str]) -> List[str]:
    """
    Extract file paths from list of strings using extension-based filtering.
    
    Filters strings to identify those that appear to be file paths by checking
    for known file extensions common in embedded systems. Applies additional
    validation to ensure the strings look like reasonable file paths.
    
    Args:
        strings (List[str]): List of strings to filter for file paths
        
    Returns:
        List[str]: List of strings that appear to be file paths
    """
    files = []
    
    # Define known file extensions for embedded systems
    valid_extensions = {
        '.bin', '.txt', '.json', '.cfg', '.conf', '.py', '.c', '.h', '.html', 
        '.css', '.js', '.cpp', '.hpp', '.xml', '.log', '.ini', '.dat', '.hex',
        '.elf', '.img', '.fw', '.rom', '.nvs', '.csv', '.pem', '.crt', '.key',
        '.md', '.rst', '.yml', '.yaml', '.toml', '.sh', '.bat', '.lua', '.php'
    }
    
    for string in strings:
        # Only accept strings that end with valid extensions
        if any(string.lower().endswith(ext) for ext in valid_extensions):
            # Additional validation: should look like a reasonable file path
            if len(string) >= 3 and len(string) <= 150:  # Reasonable length
                # Should not contain too many special characters that indicate it's not a file
                special_chars = sum(1 for c in string if c in '!@#$%^&*()+=[]{}|\\:";\'<>?`~')
                if special_chars <= len(string) * 0.2:  # Max 20% special characters
                    files.append(string.strip())
    
    return list(set(files))  # Remove duplicates

def _format_files_output(files: List[str], chip_type: ChipType, base_address: int) -> Tuple[str, int]:
    """
    Format file path analysis results for terminal display.
    
    Creates formatted output with ANSI color codes showing file path analysis
    summary and categorized file lists organized by file extension. Groups
    files by type for easier analysis.
    
    Args:
        files (List[str]): List of file paths found in firmware
        chip_type (ChipType): Detected chip type for display
        base_address (int): Base address for display
        
    Returns:
        Tuple[str, int]: A tuple containing:
            - str: Formatted output string with ANSI colors
            - int: Status code (1 for success, 0 for failure)
    """
    status = 1
    output = []
    output.append("\033[38;5;169m==============================================================================================\033[0m")
    output.append(f"\033[38;5;72mAnalyzing firmware: {len(files)} files ({chip_type.value.upper()})")
    output.append(f"Base address: 0x{base_address:08X}\033[0m")
    output.append("")
    
    if not files:
        status = 0
        return "", status
    
    output.append(f"\033[38;5;183mFound {len(files)} file path(s)\033[0m")
    output.append("")
    
    # Categorize files by extension
    categories = {}
    for file_path in files:
        if '.' in file_path:
            ext = file_path.split('.')[-1].lower()
            if ext not in categories:
                categories[ext] = []
            categories[ext].append(file_path)
        else:
            if 'no_extension' not in categories:
                categories['no_extension'] = []
            categories['no_extension'].append(file_path)
    
    for category, file_list in categories.items():
        if category == 'no_extension':
            output.append("\033[38;5;220mFILES WITHOUT EXTENSION:\033[0m")
        else:
            output.append(f"\033[38;5;220m{category.upper()} FILES:\033[0m")
        output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
        for file_path in file_list:
            output.append(f"\033[0m  - {file_path}\033[0m")
        output.append("")
    
    return "\n".join(output), status