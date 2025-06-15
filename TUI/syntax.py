from .baseplate import *
from .globals import *
import re

class SyntaxHighlight(baseplate):
    def create_highlighted_disasm(self, text: str) -> Text:
        rich_text = Text()
        lines = text.split('\n')

        for i, line in enumerate(lines):
            if i > 0:
                rich_text.append('\n')

            if not line.strip():
                rich_text.append(line)
                continue
            
            if line.strip().startswith('0x') and ' ' in line:
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    addr = parts[0].strip()
                    rest = parts[1].strip()
                    rich_text.append(addr, style=f"bold {galaxy_warning.hex}")
                    rich_text.append(': ')
                    self.highlight_instruction_line(rich_text, rest)
                else:
                    rich_text.append(line)
            elif line.strip().startswith(';'):
                rich_text.append(line, style=galaxy_secondary.hex)
            elif line.strip().startswith('--'):
                rich_text.append(line, style=f"dim {galaxy_accent.hex}")
            elif line.strip().startswith('0x'):
                rich_text.append(line, style=galaxy_warning.hex)
            else:
                self.highlight_misc_line(rich_text, line)

        return rich_text

    def highlight_instruction_line(self, rich_text: Text, line: str) -> None:
        parts = line.split()
        if not parts:
            rich_text.append(line)
            return

        instruction = parts[0]
        rich_text.append(instruction, style=f"bold {galaxy_primary.hex}")

        if len(parts) > 1:
            rich_text.append(' ')
            operands = ' '.join(parts[1:])
            self.highlight_operands(rich_text, operands)

    def highlight_operands(self, rich_text: Text, operands: str) -> None:

        last_end = 0
        for match in re.finditer(r'\b(a\d+|sp|ra|v\d+|t\d+)\b', operands):
            if match.start() > last_end:
                rich_text.append(operands[last_end:match.start()])
            rich_text.append(match.group(), style=galaxy_accent.hex)
            last_end = match.end()

        remaining = operands[last_end:]
        if remaining:
            last_end = 0
            for match in re.finditer(r'\b0x[0-9a-fA-F]+\b', remaining):
                if match.start() > last_end:
                    rich_text.append(remaining[last_end:match.start()])
                rich_text.append(match.group(), style=galaxy_warning.hex)
                last_end = match.end()

            if last_end < len(remaining):
                final_text = remaining[last_end:]
                rich_text.append(final_text, style=galaxy_contrast_text.hex)

    def create_highlighted_hex(self, text: str) -> Text:
        rich_text = Text()
        lines = text.split('\n')

        for i, line in enumerate(lines):
            if i > 0:
                rich_text.append('\n')

            if not line.strip():
                rich_text.append(line)
                continue
            
            # Header lines and separators
            if line.strip().startswith('='):
                rich_text.append(line, style=f"dim {galaxy_accent.hex}")
            elif line.strip().startswith('HEX VIEWER -'):
                rich_text.append('HEX VIEWER - ', style=galaxy_secondary.hex)
                filename = line.replace('HEX VIEWER - ', '').strip()
                rich_text.append(filename, style=galaxy_primary.hex)
            elif re.match(r'^[0-9A-Fa-f]{8}\s+', line):
                # Hex dump lines - better pattern matching for offset
                self.highlight_hex_dump_line(rich_text, line)
            else:
                rich_text.append(line)

        return rich_text

    def highlight_hex_dump_line(self, rich_text: Text, line: str) -> None:
        """Highlight individual hex dump lines using regex pattern matching"""
        # Use regex to match the hex dump line format: 8 hex digits + spaces + hex data + ASCII
        hex_line_pattern = r'^([0-9A-Fa-f]{8})(\s+.*)'
        match = re.match(hex_line_pattern, line)
        
        if not match:
            rich_text.append(line)
            return
        
        offset = match.group(1)
        rest_of_line = match.group(2)
        
        # Highlight offset in grey
        rich_text.append(offset, style="dim")
        
        # Process the rest character by character to preserve spacing and highlight dots
        in_ascii_section = False
        for i, char in enumerate(rest_of_line):
            # Detect if we're in the ASCII section (after sufficient hex data spacing)
            # With 24 bytes per line, ASCII section starts around position 75+
            if not in_ascii_section and i > 75:  # ASCII section starts after hex data + spacing
                in_ascii_section = True
            
            if char == '.':
                rich_text.append(char, style="dim")
            elif in_ascii_section and char.isprintable() and char not in ' \t':
                # Highlight actual ASCII characters in accent color
                rich_text.append(char, style=galaxy_accent.hex)
            else:
                rich_text.append(char)

    def highlight_misc_line(self, rich_text: Text, line: str) -> None:
        if 'fcn.' in line:
            parts = line.split('fcn.')
            rich_text.append(parts[0])
            for i, part in enumerate(parts[1:], 1):
                rich_text.append('fcn.', style=f"bold {galaxy_primary.hex}")
                func_end = 0
                for char in part:
                    if char.isalnum() or char in '._':
                        func_end += 1
                    else:
                        break
                if func_end > 0:
                    rich_text.append(part[:func_end], style=galaxy_primary.hex)
                    rich_text.append(part[func_end:])
                else:
                    rich_text.append(part)
        else:
            rich_text.append(line)