from typing import List, Dict, Tuple

def extract_strings_from_firmware(firmware_path: str) -> Tuple[str, int]:
    status = 1
    try:
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        # Extract strings
        strings = _extract_strings(firmware_data)
        
        # Analyze strings for interesting patterns
        string_analysis = _analyze_strings(strings)
        
        return _format_strings_output(string_analysis, len(strings))
        
    except Exception as e:
        status = 0
        return f"Error extracting strings: {str(e)}", status

def _extract_strings(firmware_data: bytes, min_length: int = 4, max_length: int = 200) -> List[str]:
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
    analysis = {
        "wifi_related": [],
        "version_info": [],
        "device_info": [],
        "certificates": [],
        "esp32_functions": [],
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
        elif any(keyword in string_lower for keyword in ['esp32', 'device', 'serial', 'mac', 'chip', 'board']):
            analysis["device_info"].append(string)
        
        # Certificates
        elif '-----BEGIN' in string or '-----END' in string or 'CERTIFICATE' in string:
            analysis["certificates"].append(string)
        
        # ESP32 function names
        elif any(func in string for func in ['esp_', 'nvs_', 'gpio_', 'uart_', 'spi_', 'i2c_', 'timer_', 'task_']):
            analysis["esp32_functions"].append(string)
        
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

def _format_strings_output(string_analysis: Dict, total_strings: int) -> Tuple[str, int]:
    status = 1
    if total_strings == 0:
        status = 0
        return "", status
    output = []
    output.append("=" * 60)
    output.append("ESP FIRMWARE STRINGS ANALYSIS")
    output.append("=" * 60)
    output.append("")
    output.append(f"Total Strings Found: {total_strings}")
    output.append("")
    
    category_names = {
        "wifi_related": "WiFi Related",
        "version_info": "Version Info",
        "device_info": "Device Info",
        "esp32_functions": "ESP32 Functions",
        "config_keys": "Configuration Keys",
        "debug_messages": "Debug Messages",
        "certificates": "Certificates"
    }
    
    for key, items in string_analysis.items():
        if items:
            display_name = category_names.get(key, key.replace('_', ' ').title()) or key
            output.append(f"{display_name.upper()} ({len(items)}):")
            output.append("-" * 40)
            for item in items:
                output.append(f"  - {item[:80]}{'...' if len(item) > 80 else ''}")
            output.append("")
    
    return "\n".join(output), status