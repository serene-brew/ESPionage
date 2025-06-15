import os

def hex_viewer(filename, bytes_per_line=16):
    try:
        if not os.path.exists(filename):
            return f"Error: File '{filename}' not found!"
        
        output_lines = []
        file_size = os.path.getsize(filename)
        
        if file_size == 0:
            return f"Error: File '{filename}' is empty!"
        
        output_lines.append("=" * 77)
        output_lines.append(f"HEX VIEWER - {os.path.basename(filename)}")
        output_lines.append(f"File path: {filename}")
        output_lines.append(f"File size: {file_size:,} bytes ({file_size:X} hex)")
        output_lines.append("=" * 77)
        output_lines.append("")
        
        header_hex = ""
        for i in range(bytes_per_line):
            header_hex += f"{i:02X} "
            if i == 7:  # Add extra space after column 07
                header_hex += " "
        output_lines.append("Offset    " + header_hex + "  ASCII")
        output_lines.append("=" * 77)
        
        with open(filename, 'rb') as f:
            offset = 0
            line_count = 0
            max_lines = 10000  # Limit output for large files to prevent UI freezing
            
            while True:
                data = f.read(bytes_per_line)
                if not data:
                    break
                
                if line_count >= max_lines:
                    output_lines.append("...")
                    output_lines.append(f"[Output truncated - showing first {max_lines} lines]")
                    output_lines.append(f"[File continues for {file_size - offset:,} more bytes]")
                    break
                
                offset_str = f"{offset:08X}"
                
                hex_str = ""
                for i, byte in enumerate(data):
                    hex_str += f"{byte:02X} "
                    if i == 7:  # Add extra space in the middle
                        hex_str += " "
                
                hex_str = hex_str.ljust(50)
                
                ascii_str = ""
                for byte in data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        ascii_str += chr(byte)
                    else:
                        ascii_str += "."
                
                output_lines.append(f"{offset_str}  {hex_str} {ascii_str}")
                
                offset += len(data)
                line_count += 1
        
        output_lines.append("=" * 77)
        if line_count < max_lines:
            output_lines.append(f"Total bytes read: {offset:,}")
        else:
            output_lines.append(f"Displayed bytes: {offset:,} of {file_size:,} total")
        
        return "\n".join(output_lines)
        
    except PermissionError:
        return f"Error: Permission denied accessing file '{filename}'"
    except OSError as e:
        return f"Error: Cannot read file '{filename}' - {str(e)}"
    except Exception as e:
        return f"Error: Unexpected error reading file '{filename}' - {str(e)}"

# def main():
#     filename = "firmware.bin"
    
#     print("ESP32 Firmware Hex Viewer")
#     print("=" * 77)
#     print()
    
#     result = hex_viewer(filename)
    
#     if result:
#         print(result)
        
#         # output_filename = "firmware_hex_dump.txt"
#         # try:
#         #     with open(output_filename, 'w') as f:
#         #         f.write(result)
#         #     print(f"\nHex dump saved to: {output_filename}")
#         # except Exception as e:
#         #     print(f"Error saving to file: {e}")
#     else:
#         print("Failed to generate hex dump")

# if __name__ == "__main__":
#     main()