#!/usr/bin/env python3
import struct
import sys
import argparse
import os
import math
from typing import List, Tuple, Dict, Optional, Set
from dataclasses import dataclass
from enum import Enum
from collections import Counter, defaultdict
import statistics

class ChipType(Enum):
    ESP32 = "esp32"
    ESP8266 = "esp8266"
    UNKNOWN = "unknown"

@dataclass
class JumpTableEntry:
    offset: int
    target_address: int
    instruction_bytes: bytes
    confidence: float = 1.0

@dataclass
class JumpTable:
    base_offset: int
    base_address: int
    entries: List[JumpTableEntry]
    table_register: str
    index_register: str
    switch_instruction_offset: int
    confidence: float
    detection_method: str
    entry_size: int = 4
    gaps: List[int] = None  # Positions where gaps were found

class ChipDetector:
    
    @staticmethod
    def detect_chip_type(firmware_data: bytes) -> Tuple[ChipType, int, dict]:
        analysis = {
            'size': len(firmware_data),
            'entropy': ChipDetector._calculate_entropy(firmware_data[:1024]),
            'instruction_patterns': ChipDetector._analyze_instruction_patterns(firmware_data),
            'string_patterns': ChipDetector._find_chip_strings(firmware_data),
            'memory_layout': ChipDetector._analyze_memory_layout(firmware_data)
        }
        
        chip_strings = analysis['string_patterns']
        if 'esp32' in chip_strings:
            return ChipType.ESP32, 0x40000000, analysis
        elif 'esp8266' in chip_strings or '8266' in chip_strings:
            return ChipType.ESP8266, 0x40000000, analysis
        
        size = len(firmware_data)
        if size > 2 * 1024 * 1024:  # > 2MB typically ESP32
            return ChipType.ESP32, 0x40000000, analysis
        elif size < 1024 * 1024:  # < 1MB typically ESP8266
            return ChipType.ESP8266, 0x40000000, analysis
        
        inst_patterns = analysis['instruction_patterns']
        esp32_score = inst_patterns.get('esp32_indicators', 0)
        esp8266_score = inst_patterns.get('esp8266_indicators', 0)
        
        if esp32_score > esp8266_score:
            return ChipType.ESP32, 0x40000000, analysis
        elif esp8266_score > esp32_score:
            return ChipType.ESP8266, 0x40000000, analysis
        
        if size > 512 * 1024:
            return ChipType.ESP32, 0x40000000, analysis
        else:
            return ChipType.ESP8266, 0x40000000, analysis
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        
        import math
        
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def _analyze_instruction_patterns(firmware_data: bytes) -> dict:
        """Analyze instruction patterns to identify chip type"""
        patterns = {
            'esp32_indicators': 0,
            'esp8266_indicators': 0,
            'total_instructions': 0
        }
        
        for i in range(0, len(firmware_data) - 4, 2):
            try:
                instr = struct.unpack('<H', firmware_data[i:i+2])[0]
                patterns['total_instructions'] += 1
                
                if (instr & 0xFF0F) == 0x0004:  # More complex addressing modes
                    patterns['esp32_indicators'] += 1
                
                if (instr & 0xF00F) == 0x1000:  # Simpler branch patterns
                    patterns['esp8266_indicators'] += 1
                    
            except struct.error:
                continue
        
        return patterns
    
    @staticmethod
    def _find_chip_strings(firmware_data: bytes) -> set:
        """Find chip identification strings in firmware"""
        strings = set()
        
        try:
            text = firmware_data.decode('ascii', errors='ignore').lower()
            
            chip_indicators = ['esp32', 'esp8266', '8266', 'xtensa', 'espressif']
            
            for indicator in chip_indicators:
                if indicator in text:
                    strings.add(indicator)
                    
        except:
            pass
        
        return strings
    
    @staticmethod
    def _analyze_memory_layout(firmware_data: bytes) -> dict:
        layout = {
            'code_density': 0.0,
            'data_density': 0.0,
            'null_regions': 0
        }
        
        sample_size = min(1024, len(firmware_data))
        
        code_patterns = 0
        for i in range(0, sample_size - 2, 2):
            try:
                word = struct.unpack('<H', firmware_data[i:i+2])[0]
                if word != 0 and word != 0xFFFF:
                    # Check if it looks like an instruction
                    if (word & 0x000F) in [0x0000, 0x0001, 0x0002]:  # Common Xtensa opcodes
                        code_patterns += 1
            except:
                continue
        
        layout['code_density'] = code_patterns / (sample_size // 2) if sample_size > 0 else 0
        
        return layout

class EnhancedXtensaDisassembler:
    
    def __init__(self, chip_type: ChipType, base_address: int = 0x40000000):
        self.chip_type = chip_type
        self.base_address = base_address
        
        if chip_type == ChipType.ESP32:
            self.memory_regions = {
                'iram': (0x40000000, 0x40400000),
                'dram': (0x3F400000, 0x3F800000),
                'flash': (0x400C0000, 0x40800000),
                'rtc': (0x50000000, 0x50002000)
            }
        else:
            self.memory_regions = {
                'iram': (0x40000000, 0x40300000),
                'dram': (0x3FFE8000, 0x40000000),
                'flash': (0x40200000, 0x40300000)
            }

    def is_valid_code_address(self, addr: int) -> bool:
        for region_name, (start, end) in self.memory_regions.items():
            if region_name in ['iram', 'flash'] and start <= addr < end:
                return True
        return False

    def is_valid_data_address(self, addr: int) -> bool:
        for start, end in self.memory_regions.values():
            if start <= addr < end:
                return True
        return False

    def get_instruction_size(self, instruction: int) -> int:
        if (instruction & 0x8) == 0:
            return 3
        else:
            return 2

    def decode_l32r(self, instruction: int, pc: int) -> Optional[int]:
        if (instruction & 0x00F00F) == 0x000001:
            imm16 = (instruction >> 8) & 0xFFFF
            if imm16 & 0x8000:
                imm16 |= 0xFFFF0000
            target = (pc & 0xFFFFFFFC) + (imm16 << 2) + 4
            return target & 0xFFFFFFFF
        return None

    def analyze_instruction_context(self, firmware_data: bytes, offset: int, window: int = 40) -> dict:
        context = {
            'l32r_count': 0,
            'jump_count': 0,
            'add_count': 0,
            'load_count': 0,
            'branch_density': 0.0
        }
        
        start = max(0, offset - window)
        end = min(len(firmware_data), offset + window)
        
        for i in range(start, end, 2):
            if i + 2 > len(firmware_data):
                break
                
            try:
                instr = struct.unpack('<H', firmware_data[i:i+2])[0]
                
                if (instr & 0x00F00F) == 0x000001:  # L32R
                    context['l32r_count'] += 1
                elif (instr & 0xFFFF00FF) == 0x0000A0:  # JX
                    context['jump_count'] += 1
                elif (instr & 0xF00F) == 0xA000:  # ADD.N
                    context['add_count'] += 1
                elif (instr & 0x00F) == 0x002:  # L32I
                    context['load_count'] += 1
                    
            except struct.error:
                continue
        
        total_instructions = (end - start) // 2
        if total_instructions > 0:
            context['branch_density'] = (context['jump_count'] + context['l32r_count']) / total_instructions
        
        return context

class EnhancedJumpTableFinder:
    
    def __init__(self, firmware_data: bytes, chip_type: ChipType = None, base_address: int = None):
        self.firmware_data = firmware_data
        
        if chip_type is None or base_address is None:
            detected_chip, detected_base, self.detection_info = ChipDetector.detect_chip_type(firmware_data)
            self.chip_type = chip_type or detected_chip
            self.base_address = base_address or detected_base
        else:
            self.chip_type = chip_type
            self.base_address = base_address
            self.detection_info = {}
        
        self.disasm = EnhancedXtensaDisassembler(self.chip_type, self.base_address)
        self.jump_tables: List[JumpTable] = []
        
    def read_instruction(self, offset: int) -> Optional[int]:
        if offset + 2 > len(self.firmware_data):
            return None
        
        try:
            instr16 = struct.unpack('<H', self.firmware_data[offset:offset+2])[0]
            
            if (instr16 & 0x8) == 0:  # 24-bit instruction
                if offset + 3 > len(self.firmware_data):
                    return None
                third_byte = self.firmware_data[offset + 2]
                return instr16 | (third_byte << 16)
            else:  # 16-bit instruction
                return instr16
        except struct.error:
            return None

    def read_word(self, offset: int) -> Optional[int]:
        if offset + 4 > len(self.firmware_data):
            return None
        try:
            return struct.unpack('<L', self.firmware_data[offset:offset+4])[0]
        except struct.error:
            return None

    def find_enhanced_l32r_sequences(self) -> List[Tuple[int, int, dict]]:
        sequences = []
        
        for offset in range(0, len(self.firmware_data) - 3, 1):
            instruction = self.read_instruction(offset)
            if instruction is None:
                continue
                
            pc = self.base_address + offset
            target_addr = self.disasm.decode_l32r(instruction, pc)
            
            if target_addr and self.disasm.is_valid_data_address(target_addr):
                context = self.disasm.analyze_instruction_context(self.firmware_data, offset)
                sequences.append((offset, target_addr, context))
        
        return sequences

    def analyze_table_entries_advanced(self, table_offset: int, max_entries: int = 1024) -> Tuple[List[JumpTableEntry], dict]:
        entries = []
        stats = {
            'total_checked': 0,
            'valid_addresses': 0,
            'invalid_addresses': 0,
            'gaps': [],
            'address_distribution': [],
            'confidence_score': 0.0
        }
        
        consecutive_invalid = 0
        max_consecutive_invalid = 3
        
        for i in range(max_entries):
            entry_offset = table_offset + (i * 4)
            entry_value = self.read_word(entry_offset)
            stats['total_checked'] += 1
            
            if entry_value is None:
                break
            
            if self.disasm.is_valid_code_address(entry_value):
                entries.append(JumpTableEntry(
                    offset=entry_offset,
                    target_address=entry_value,
                    instruction_bytes=self.firmware_data[entry_offset:entry_offset+4],
                    confidence=self._calculate_entry_confidence(entry_value, entries)
                ))
                stats['valid_addresses'] += 1
                stats['address_distribution'].append(entry_value)
                consecutive_invalid = 0
            else:
                stats['invalid_addresses'] += 1
                consecutive_invalid += 1
                
                if entries:
                    stats['gaps'].append(i)
                
                if consecutive_invalid >= max_consecutive_invalid:
                    if len(entries) >= 2:
                        break
                    if len(entries) == 0 and i > 10:
                        break
        
        if stats['total_checked'] > 0:
            valid_ratio = stats['valid_addresses'] / stats['total_checked']
            gap_penalty = len(stats['gaps']) * 0.1
            stats['confidence_score'] = max(0.0, valid_ratio - gap_penalty)
        
        return entries, stats

    def _calculate_entry_confidence(self, address: int, existing_entries: List[JumpTableEntry]) -> float:
        confidence = 1.0
        
        if not existing_entries:
            return confidence
        
        existing_addresses = [e.target_address for e in existing_entries]
        min_addr = min(existing_addresses)
        max_addr = max(existing_addresses)
        
        if address < min_addr or address > max_addr:
            distance = min(abs(address - min_addr), abs(address - max_addr))
            if distance > 0x1000:  # 4KB threshold
                confidence *= 0.8
            if distance > 0x10000:  # 64KB threshold
                confidence *= 0.5
        
        if len(existing_addresses) >= 2:
            addr_diffs = [existing_addresses[i+1] - existing_addresses[i] 
                         for i in range(len(existing_addresses)-1)]
            if addr_diffs:
                avg_diff = statistics.mean(addr_diffs)
                expected_addr = existing_addresses[-1] + avg_diff
                if abs(address - expected_addr) < avg_diff * 0.5:
                    confidence *= 1.2  # Bonus for following pattern
        
        return min(confidence, 1.0)

    def validate_jump_table_advanced(self, table_offset: int, l32r_offset: int, jx_offset: int) -> Optional[JumpTable]:
        
        entries, stats = self.analyze_table_entries_advanced(table_offset)
        
        validation_score = 0.0
        reasons = []
        
        # Minimum entry count (relaxed)
        # if len(entries) >= 2:
        #     validation_score += 0.3
        #     reasons.append("sufficient_entries")
        # else:
        #     return None
  
        if len(entries) >= 4:  # Changed from 2 to 4
            validation_score += 0.3
            reasons.append("sufficient_entries")
        elif len(entries) >= 2:
            validation_score += 0.1  # Lower score for small tables
            reasons.append("minimal_entries")
        else:
            return None
        if stats['confidence_score'] > 0.6:
            validation_score += 0.3
            reasons.append("high_confidence")
        elif stats['confidence_score'] > 0.4:
            validation_score += 0.2
            reasons.append("medium_confidence")
        
        if len(entries) >= 2:
            addresses = [e.target_address for e in entries]
            addr_range = max(addresses) - min(addresses)
            
            if addr_range <= 0x1000:
                validation_score += 0.2
                reasons.append("tight_clustering")
            elif addr_range <= 0x10000:
                validation_score += 0.1
                reasons.append("reasonable_clustering")
            elif addr_range <= 0x100000:
                validation_score += 0.05
                reasons.append("loose_clustering")
        
        context = self.disasm.analyze_instruction_context(self.firmware_data, l32r_offset)
        if context['branch_density'] > 0.3:  # High branch density indicates switch-like code
            validation_score += 0.15
            reasons.append("high_branch_density")
        
        gap_ratio = len(stats['gaps']) / len(entries) if entries else 1.0
        if gap_ratio <= 0.2:  # Few gaps
            validation_score += 0.05
            reasons.append("few_gaps")
        # Gap tolerance (stricter)
        # gap_ratio = len(stats['gaps']) / len(entries) if entries else 1.0
        # if gap_ratio <= 0.1:  # Very few gaps
        #     validation_score += 0.1
        #     reasons.append("very_few_gaps")
        # elif gap_ratio <= 0.2:  # Few gaps
        #     validation_score += 0.05
        #     reasons.append("few_gaps")
        # elif gap_ratio > 0.5:  # Too many gaps
        #     validation_score -= 0.2  # Penalty for excessive gaps
        #     reasons.append("excessive_gaps")
        # # Require minimum validation score
        # if validation_score < 0.5:
        #     return None
        
        return JumpTable(
            base_offset=table_offset,
            base_address=self.base_address + table_offset,
            entries=entries,
            table_register="a?",
            index_register="a?",
            switch_instruction_offset=jx_offset,
            confidence=validation_score,
            detection_method=", ".join(reasons),
            gaps=stats['gaps'] if stats['gaps'] else None
        )
    
    def find_jump_tables_enhanced(self) -> Tuple[List[JumpTable], str]:
        analysis_output = []
        analysis_output.append("\033[32m==============================================================================================\033[0m")
        analysis_output.append(f"Analyzing firmware: {len(self.firmware_data)} bytes ({self.chip_type.value})")
        analysis_output.append(f"Base address: 0x{self.base_address:08X}")

        l32r_sequences = self.find_enhanced_l32r_sequences()
        analysis_output.append(f"Found {len(l32r_sequences)} L32R sequences with context")

        jump_tables = []
        processed_tables = set()

        l32r_sequences.sort(key=lambda x: x[2]['branch_density'], reverse=True)

        for l32r_offset, table_addr, context in l32r_sequences:
            table_key = (table_addr // 16) * 16
            if table_key in processed_tables:
                continue
            processed_tables.add(table_key)

            jump_table = self.analyze_potential_jump_table_enhanced(l32r_offset, table_addr, context)
            if jump_table:
                jump_tables.append(jump_table)

        additional_tables = self.find_standalone_address_arrays()
        jump_tables.extend(additional_tables)

        if len(additional_tables) > 0:
            analysis_output.append(f"Found {len(additional_tables)} additional standalone address arrays")

        self.jump_tables = sorted(jump_tables, key=lambda x: x.confidence, reverse=True)
        return self.jump_tables, "\n".join(analysis_output)

    def _print_context_hex_dump(self, base_offset: int, table_size: int, context_before: int = 16, context_after: int = 16):
        start_offset = max(0, base_offset - context_before)
        end_offset = min(len(self.firmware_data), base_offset + table_size + context_after)
        
        start_offset = (start_offset // 16) * 16
        end_offset = ((end_offset + 15) // 16) * 16
        end_offset = min(end_offset, len(self.firmware_data))
        
        table_start = base_offset
        table_end = base_offset + table_size
        
        for offset in range(start_offset, end_offset, 16):
            hex_bytes = []
            ascii_repr = []
            
            for j in range(16):
                if offset + j < len(self.firmware_data):
                    byte_val = self.firmware_data[offset + j]
                    hex_bytes.append(f"{byte_val:02x}")
                    ascii_repr.append(chr(byte_val) if 32 <= byte_val <= 126 else '.')
                else:
                    hex_bytes.append("  ")
                    ascii_repr.append(" ")
            
            hex_str = " ".join(hex_bytes[:8]) + "  " + " ".join(hex_bytes[8:])
            ascii_str = "".join(ascii_repr)
            
            line_start = offset
            line_end = min(offset + 16, len(self.firmware_data))
            is_table_line = not (line_end <= table_start or line_start >= table_end)
            
            marker = ">>> " if is_table_line else "    "
            print(f"{marker}{offset:08x}: {hex_str} |{ascii_str}|")
    def analyze_potential_jump_table_enhanced(self, l32r_offset: int, table_addr: int, context: dict) -> Optional[JumpTable]:
        
        if table_addr < self.base_address:
            return None
        
        table_offset = table_addr - self.base_address
        if table_offset >= len(self.firmware_data):
            return None
        
        search_window = 60 if context['branch_density'] > 0.3 else 40
        current_offset = l32r_offset
        
        for i in range(search_window):
            if current_offset + 3 >= len(self.firmware_data):
                break
                
            instruction = self.read_instruction(current_offset)
            if instruction is None:
                break
            
            if (instruction & 0xFFFF00FF) == 0x0000A0:  # JX
                return self.validate_jump_table_advanced(table_offset, l32r_offset, current_offset)
            
            current_offset += self.disasm.get_instruction_size(instruction)
        
        return None

    def find_standalone_address_arrays(self) -> List[JumpTable]:
        standalone_tables = []
        
        for offset in range(0, len(self.firmware_data) - 16, 4):  # 4-byte aligned
            if offset % 1000 == 0:  # Progress indicator for large files
                continue
                
            consecutive_valid = 0
            addresses = []
            
            for i in range(8):  # Check up to 8 consecutive addresses
                word_offset = offset + (i * 4)
                word = self.read_word(word_offset)
                
                if word and self.disasm.is_valid_code_address(word):
                    consecutive_valid += 1
                    addresses.append(word)
                else:
                    break
            
            if consecutive_valid >= 3:
                entries, stats = self.analyze_table_entries_advanced(offset)
                
                if len(entries) >= 3 and stats['confidence_score'] > 0.7:
                    table_addr = self.base_address + offset
                    duplicate = False
                    for existing in self.jump_tables:
                        if abs(existing.base_address - table_addr) < 16:
                            duplicate = True
                            break
                    
                    if not duplicate:
                        standalone_table = JumpTable(
                            base_offset=offset,
                            base_address=table_addr,
                            entries=entries,
                            table_register="unknown",
                            index_register="unknown",
                            switch_instruction_offset=-1,
                            confidence=stats['confidence_score'] * 0.8,  # Slightly lower confidence
                            detection_method="standalone_array",
                            gaps=stats['gaps'] if stats['gaps'] else None
                        )
                        standalone_tables.append(standalone_table)
        
        print(f"Found {len(standalone_tables)} additional standalone address arrays")
        return standalone_tables
    def _get_context_hex_dump_string(self, base_offset: int, table_size: int, context_before: int = 16, context_after: int = 16) -> str:
        hex_lines = []
        start_offset = max(0, base_offset - context_before)
        end_offset = min(len(self.firmware_data), base_offset + table_size + context_after)

        start_offset = (start_offset // 16) * 16
        end_offset = ((end_offset + 15) // 16) * 16
        end_offset = min(end_offset, len(self.firmware_data))

        table_start = base_offset
        table_end = base_offset + table_size

        for offset in range(start_offset, end_offset, 16):
            hex_bytes = []
            ascii_repr = []

            for j in range(16):
                if offset + j < len(self.firmware_data):
                    byte_val = self.firmware_data[offset + j]
                    hex_bytes.append(f"{byte_val:02x}")
                    ascii_repr.append(chr(byte_val) if 32 <= byte_val <= 126 else '.')
                else:
                    hex_bytes.append("  ")
                    ascii_repr.append(" ")

            hex_str = " ".join(hex_bytes[:8]) + "  " + " ".join(hex_bytes[8:])
            ascii_str = "".join(ascii_repr)

            line_start = offset
            line_end = min(offset + 16, len(self.firmware_data))
            is_table_line = not (line_end <= table_start or line_start >= table_end)

            marker = ">>> " if is_table_line else "    "
            hex_lines.append(f"{marker}{offset:08x}: {hex_str} |{ascii_str}|")

        return "\n".join(hex_lines)

    def print_enhanced_results(self) -> Tuple[str, int]:
        status = 1
        output_lines = []

        if not self.jump_tables:
            status = 0
            return "", status 

        output_lines.append(f"Found {len(self.jump_tables)} jump table(s)\n")

        for i, jt in enumerate(self.jump_tables, 1):
            output_lines.append("----------------------------------------------------------------------------------------------")
            output_lines.append(f"Jump Table #{i}:")
            output_lines.append(f"  Location: 0x{jt.base_address:08X} (offset 0x{jt.base_offset:08X})")
            output_lines.append(f"  Entries: {len(jt.entries)}")
            output_lines.append(f"  Confidence: {jt.confidence:.2f}")

            if jt.switch_instruction_offset >= 0:
                switch_addr = self.base_address + jt.switch_instruction_offset
                output_lines.append(f"  Switch instruction: 0x{switch_addr:08X}")

            output_lines.append(f"  Context (offset 0x{jt.base_offset:08X}):")
            # Get hex dump as string instead of printing
            hex_dump = self._get_context_hex_dump_string(jt.base_offset, len(jt.entries) * 4)
            output_lines.append(hex_dump)

            output_lines.append(f"  Targets:")
            if len(jt.entries) <= 6:
                for j, entry in enumerate(jt.entries):
                    confidence_str = f" (conf: {entry.confidence:.2f})" if entry.confidence < 1.0 else ""
                    output_lines.append(f"    [{j:2d}] 0x{entry.target_address:08X}{confidence_str}")
            else:
                entries_per_col = 6
                num_cols = (len(jt.entries) + entries_per_col - 1) // entries_per_col

                for row in range(entries_per_col):
                    line_parts = []
                    for col in range(num_cols):
                        idx = col * entries_per_col + row
                        if idx < len(jt.entries):
                            entry = jt.entries[idx]
                            confidence_str = f" (conf: {entry.confidence:.2f})" if entry.confidence < 1.0 else ""
                            line_parts.append(f"[{idx:2d}] 0x{entry.target_address:08X}{confidence_str}")
                        else:
                            line_parts.append("")  # Empty space for alignment

                    if any(part.strip() for part in line_parts):
                        formatted_line = "  " + "".join(f"{part:<20}" for part in line_parts)
                        output_lines.append(formatted_line.rstrip())
            output_lines.append("")

        return "\n".join(output_lines), status

def ShowJumpTables(firmware_path) -> Tuple[str, int]:
    try:
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
    except FileNotFoundError:
        return f"Error: Firmware file '{firmware_path}' not found"
    except Exception as e:
        return f"Error reading firmware file: {e}"
    
    finder = EnhancedJumpTableFinder(firmware_data)
    
    jump_tables, analysis_output = finder.find_jump_tables_enhanced()
    results_output, status = finder.print_enhanced_results()
    
    # Combine analysis and results
    complete_output = analysis_output + "\n\n" + results_output
    return complete_output, status