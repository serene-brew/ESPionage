"""
Author: Imon Chakraborty (RiserSama)
ESP Firmware URL Extractor

This module provides functionality to extract and analyze URLs from ESP32 and ESP8266 firmware.
It identifies strings that appear to be URLs by looking for common protocols and validating
URL structure. This helps security researchers and developers discover network endpoints,
API endpoints, update servers, and other network resources referenced in the firmware.

The extractor supports various protocols commonly used in IoT devices including HTTP/HTTPS,
MQTT, WebSocket, CoAP, and others. It performs validation to ensure extracted strings are
legitimate URLs and not false positives from binary data.

Main features:
- String extraction from firmware binaries
- Multi-protocol URL detection (HTTP, HTTPS, MQTT, WebSocket, CoAP, etc.)
- URL validation using structure heuristics
- Protocol-specific filtering
- Domain structure validation
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

def extract_urls_from_firmware(firmware_path: str) -> Tuple[str, int]:
    """
    Extract and analyze URLs from ESP firmware.
    
    Main entry point for URL extraction. Reads the firmware file,
    extracts strings, filters for URLs, and returns formatted
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
        
        # Filter for URLs
        urls = _extract_urls(strings)
        
        return _format_urls_output(urls, chip_type, base_address)
        
    except Exception as e:
        status = 0
        return f"Error extracting URLs: {str(e)}", status

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

def _extract_urls(strings: List[str]) -> List[str]:
    """
    Extract URLs from list of strings using protocol-based filtering.
    
    Filters strings to identify those that appear to be URLs by checking for
    known protocols common in IoT devices. Applies validation to ensure the
    strings have proper URL structure and domain-like characteristics.
    
    Args:
        strings (List[str]): List of strings to filter for URLs
        
    Returns:
        List[str]: List of strings that appear to be valid URLs
    """
    urls = []
    
    # Valid URL protocols for embedded devices
    valid_protocols = {
        'http://', 'https://', 'ftp://', 'ftps://', 'mqtt://', 'mqtts://', 
        'ws://', 'wss://', 'coap://', 'coaps://', 'tcp://', 'udp://', 
        'ssl://', 'tls://', 'file://', 'data://'
    }
    
    for string in strings:
        # Check if string contains a valid protocol
        lower_string = string.lower()
        protocol_found = False
        
        for protocol in valid_protocols:
            if protocol in lower_string:
                protocol_found = True
                break
        
        if protocol_found:
            # Additional validation to ensure it's a real URL
            if (len(string) >= 10 and len(string) <= 500 and  # Reasonable length
                not string.startswith(' ') and not string.endswith(' ') and  # No leading/trailing spaces
                string.count('://') == 1):  # Exactly one protocol separator
                
                # Extract the URL part (from protocol to end or first whitespace)
                protocol_pos = -1
                for protocol in valid_protocols:
                    pos = lower_string.find(protocol)
                    if pos != -1:
                        protocol_pos = pos
                        break
                
                if protocol_pos != -1:
                    # Find the end of URL (stop at whitespace, quotes, or other delimiters)
                    url_start = protocol_pos
                    url_part = string[url_start:]
                    
                    # Find end of URL
                    end_chars = [' ', '\t', '\n', '\r', '"', "'", '<', '>', '`', '|', '^']
                    url_end = len(url_part)
                    
                    for end_char in end_chars:
                        pos = url_part.find(end_char, 8)  # Start search after protocol
                        if pos != -1 and pos < url_end:
                            url_end = pos
                    
                    clean_url = url_part[:url_end].strip()
                    
                    # Final validation: should have domain-like structure
                    if ('.' in clean_url and 
                        len(clean_url) >= 10 and
                        not clean_url.endswith('.') and
                        clean_url.count('.') <= 10):  # Not too many dots
                        urls.append(clean_url)
    
    return list(set(urls))  # Remove duplicates

def _format_urls_output(urls: List[str], chip_type: ChipType, base_address: int) -> Tuple[str, int]:
    """
    Format URL analysis results for terminal display.
    
    Creates formatted output with ANSI color codes showing URL analysis
    summary and numbered list of discovered URLs. Provides a clean
    presentation of network endpoints found in the firmware.
    
    Args:
        urls (List[str]): List of URLs found in firmware
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
    output.append(f"\033[38;5;72mAnalyzing firmware: {len(urls)} URLs ({chip_type.value.upper()})")
    output.append(f"Base address: 0x{base_address:08X}\033[0m")
    output.append("")
    
    if not urls:
        status = 0
        return "", status
    output.append("")
    
    output.append("\033[38;5;220mEXTRACTED URLs:\033[0m")
    output.append("\033[38;5;169m----------------------------------------------------------------------------------------------\033[0m")
    for i, url in enumerate(urls, 1):
        output.append(f"\033[0m{i:3d}. {url}\033[0m")
    
    return "\n".join(output), status