"""
ESP Firmware String Extractor and Analyzer

This module provides functionality to extract and analyze strings from ESP32 and ESP8266 firmware.
It can identify printable ASCII strings within firmware binaries and categorize them based on
content patterns to reveal useful information about the firmware's functionality.

The analyzer categorizes strings into several groups including WiFi-related strings, version
information, device details, ESP function names, configuration keys, debug messages, and
certificates. This helps security researchers and developers understand firmware capabilities
and identify potential security concerns.

Main features:
- Configurable string extraction with length filtering
- Automatic string categorization based on content patterns
- WiFi credential and configuration detection
- Version and device information identification
- ESP SDK function name extraction
- Debug message and error string collection
- Certificate and cryptographic content detection
- Colored terminal output formatting
"""

from typing import List, Dict, Tuple
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

def extract_strings_from_firmware(firmware_path: str) -> Tuple[str, int]:
    """
    Extract and analyze strings from ESP firmware file.
    
    Main entry point for string extraction and analysis. Reads the firmware file,
    extracts printable ASCII strings, categorizes them by content type, and returns
    formatted analysis results suitable for terminal display.
    
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
        
        # Extract strings
        strings = _extract_strings(firmware_data)
        
        # Analyze strings for interesting patterns
        string_analysis = _analyze_strings(strings)
        
        return _format_strings_output(string_analysis, len(strings), chip_type, base_address)
        
    except Exception as e:
        status = 0
        return f"Error extracting strings: {str(e)}", status

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

def _analyze_strings(strings: List[str]) -> Dict:
    """
    Analyze extracted strings and categorize them by content patterns.
    
    Examines each string for keywords and patterns that indicate specific types
    of functionality. Categories include WiFi settings, version information,
    device details, ESP functions, configuration keys, debug messages, and certificates.
    
    Args:
        strings (List[str]): List of strings to analyze and categorize
        
    Returns:
        Dict: Dictionary with categorized strings organized by content type
    """
    analysis = {
        "wifi_related": [],
        "version_info": [],
        "device_info": [],
        "certificates": [],
        "esp_functions": [],
        "config_keys": [],
        "debug_messages": []
    }
    
    for string in strings:
        string_lower = string.lower()
        
        # WiFi related strings
        if any(keyword in string_lower for keyword in ['wifi', 'ssid', 'password', 'wpa', 'wep', 'ap_', 'sta_']):
            analysis["wifi_related"].append(string)
        
        # Version information
        elif any(keyword in string_lower for keyword in ['version', 'ver', 'build', 'revision', 'v1.', 'v2.', 'v3.', 'v4.']):
            analysis["version_info"].append(string)
        
        # Device information
        elif any(keyword in string_lower for keyword in ['esp32', 'esp8266', 'esp', 'device', 'serial', 'mac', 'chip', 'board']):
            analysis["device_info"].append(string)
        
        # Certificates
        elif '-----begin' in string_lower or '-----end' in string_lower or 'certificate' in string_lower:
            analysis["certificates"].append(string)
        
        # ESP function names
        elif any(func in string for func in ['esp_', 'nvs_', 'gpio_', 'uart_', 'spi_', 'i2c_', 'timer_', 'task_']):
            analysis["esp_functions"].append(string)
        
        # Configuration keys
        elif any(keyword in string_lower for keyword in ['config', 'setting', 'param', 'key', 'value', 'enable', 'disable']):
            analysis["config_keys"].append(string)
        
        # Debug messages
        elif any(keyword in string_lower for keyword in ['error', 'warning', 'debug', 'info', 'log', 'fail', 'success']):
            analysis["debug_messages"].append(string)
    
    # Remove duplicates
    for key in analysis:
        analysis[key] = list(set(analysis[key]))
    
    return analysis

def _format_strings_output(string_analysis: Dict, total_strings: int, chip_type: ChipType, base_address: int) -> Tuple[str, int]:
    """
    Format string analysis results for terminal display.
    
    Creates formatted output with ANSI color codes showing string analysis summary,
    categorized string lists, and statistics. Truncates long strings for readability
    while preserving important information.
    
    Args:
        string_analysis (Dict): Dictionary containing categorized strings
        total_strings (int): Total number of strings found
        chip_type (ChipType): Detected chip type for display
        base_address (int): Base address for display
        
    Returns:
        Tuple[str, int]: A tuple containing:
            - str: Formatted output string with ANSI colors
            - int: Status code (1 for success, 0 for failure)
    """
    status = 1
    if total_strings == 0:
        status = 0
        return "", status
    output = []
    output.append("\033[38;5;169m==============================================================================================\033[0m")
    output.append(f"\033[38;5;72mAnalyzing firmware: {total_strings} strings ({chip_type.value.upper()})")
    output.append(f"Base address: 0x{base_address:08X}\033[0m")
    output.append("")
    
    output.append(f"\033[38;5;183mFound {total_strings} string(s)\033[0m")
    output.append("")
    
    category_names = {
        "wifi_related": "WiFi Related",
        "version_info": "Version Info",
        "device_info": "Device Info",
        "esp_functions": "ESP Functions",
        "config_keys": "Configuration Keys",
        "debug_messages": "Debug Messages",
        "certificates": "Certificates"
    }
    
    for key, items in string_analysis.items():
        if items:
            display_name = category_names.get(key, key.replace('_', ' ').title()) or key
            output.append(f"\033[38;5;220m{display_name.upper()} ({len(items)}):\033[0m")
            output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
            for item in items:
                truncated_item = item[:80] + '...' if len(item) > 80 else item
                output.append(f"\033[0m  - {truncated_item}\033[0m")
            output.append("")
    
    return "\n".join(output), status