from typing import List

def extract_urls_from_firmware(firmware_path: str) -> str:
    try:
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        # Extract strings first
        strings = _extract_strings(firmware_data)
        
        # Filter for URLs
        urls = _extract_urls(strings)
        
        return _format_urls_output(urls)
        
    except Exception as e:
        return f"Error extracting URLs: {str(e)}"

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

def _extract_urls(strings: List[str]) -> List[str]:
    urls = []
    
    for string in strings:
        # URLs - only strings with protocol separators
        if '://' in string:
            urls.append(string)
    
    return list(set(urls))  # Remove duplicates

def _format_urls_output(urls: List[str]) -> str:
    output = []
    output.append("=" * 60)
    output.append("ESP FIRMWARE URLs ANALYSIS")
    output.append("=" * 60)
    output.append("")
    
    if not urls:
        output.append("No URLs found in firmware")
        return "\n".join(output)
    
    output.append(f"Total URLs Found: {len(urls)}")
    output.append("")
    
    output.append("EXTRACTED URLs:")
    output.append("-" * 40)
    for i, url in enumerate(urls, 1):
        output.append(f"{i:3d}. {url}")
    
    return "\n".join(output)