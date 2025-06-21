from typing import List

def extract_files_from_firmware(firmware_path: str) -> str:
    try:
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        # Extract strings first
        strings = _extract_strings(firmware_data)
        
        # Filter for file paths
        files = _extract_files(strings)
        
        return _format_files_output(files)
        
    except Exception as e:
        return f"Error extracting files: {str(e)}"

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

def _extract_files(strings: List[str]) -> List[str]:
    files = []
    
    for string in strings:
        # Files - file paths and extensions
        if (('/' in string and '.' in string) or 
            string.endswith(('.bin', '.txt', '.json', '.cfg', '.conf', '.py', '.c', '.h', '.html', '.css', '.js'))):
            files.append(string)
    
    return list(set(files))  # Remove duplicates

def _format_files_output(files: List[str]) -> str:
    output = []
    output.append("=" * 60)
    output.append("ESP FIRMWARE FILES ANALYSIS")
    output.append("=" * 60)
    output.append("")
    
    if not files:
        output.append("No file paths found in firmware")
        return "\n".join(output)
    
    output.append(f"Total File Paths Found: {len(files)}")
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
            output.append("FILES WITHOUT EXTENSION:")
        else:
            output.append(f"{category.upper()} FILES:")
        output.append("-" * 40)
        for file_path in file_list:
            output.append(f"  - {file_path}")
        output.append("")
    
    return "\n".join(output)