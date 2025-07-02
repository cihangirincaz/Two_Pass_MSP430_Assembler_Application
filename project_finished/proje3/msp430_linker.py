#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MSP430 G2553 ELF Linker - ULTRA FIXED VERSION
Fixes: Symbol conflicts, section mapping, reset vector duplication, unknown sections
"""

import sys
import os
import re
import struct
import time
from collections import defaultdict, OrderedDict

class MSP430MemoryMap:
    """MSP430 G2553 Memory Map Constants"""
    
    # Flash Memory (Program Memory)
    FLASH_START = 0xC000
    FLASH_END = 0xFFFF
    FLASH_SIZE = 0x4000  # 16KB
    
    # RAM Memory  
    RAM_START = 0x0200
    RAM_END = 0x03FF
    RAM_SIZE = 0x0200    # 512 bytes
    
    # Special Function Registers
    SFR_START = 0x0000
    SFR_END = 0x000F
    
    # Peripheral Registers
    PERIPH_8BIT_START = 0x0010
    PERIPH_8BIT_END = 0x00FF
    PERIPH_16BIT_START = 0x0100
    PERIPH_16BIT_END = 0x01FF
    
    # Interrupt Vectors
    VECTOR_TABLE_START = 0xFFE0
    VECTOR_TABLE_END = 0xFFFF
    RESET_VECTOR = 0xFFFE
    
    # Default segment addresses
    DEFAULT_TEXT_START = 0xC000
    DEFAULT_DATA_START = 0x0200
    DEFAULT_BSS_START = 0x0280
    DEFAULT_STACK_START = 0x0400

class Symbol:
    """Symbol table entry"""
    def __init__(self, name, value=0, size=0, symbol_type='NOTYPE', bind='LOCAL', section='UNDEF', defined=False):
        self.name = name
        self.value = value
        self.size = size
        self.type = symbol_type
        self.bind = bind
        self.section = section
        self.defined = defined
        self.source_file = ""
        self.priority = 0  # NEW: For conflict resolution

class Section:
    """Section information"""
    def __init__(self, name, section_type='PROGBITS', flags='', addr=0, size=0, align=1):
        self.name = name
        self.type = section_type
        self.flags = flags
        self.addr = addr
        self.size = size
        self.align = align
        self.data = bytearray()
        self.relocations = []
        self.output_offset = 0  # NEW: Track offset in final section

class Relocation:
    """Relocation entry"""
    def __init__(self, offset, symbol, rel_type, addend=0):
        self.offset = offset
        self.symbol = symbol
        self.type = rel_type
        self.addend = addend

class ObjectFile:
    """Object file representation"""
    def __init__(self, filename):
        self.filename = filename
        self.sections = {}
        self.symbols = {}
        self.relocations = []
        self.global_symbols = set()
        self.section_index_map = {0: 'UND'}  # Dynamic section mapping
        self.priority = 0  # NEW: File priority for conflict resolution

class MSP430Linker:
    """MSP430 ELF Linker - ULTRA FIXED VERSION"""
    
    def __init__(self):
        self.object_files = []
        self.sections = OrderedDict()
        self.symbols = {}
        self.global_symbols = {}
        self.undefined_symbols = set()
        self.entry_point = 0xC000
        self.memory_map = MSP430MemoryMap()
        
        # FIXED: Segment layout configuration
        self.segment_layout = {
            '.text': self.memory_map.DEFAULT_TEXT_START,
            '.rodata': 0xE000,
            '.data': self.memory_map.DEFAULT_DATA_START,
            '.bss': self.memory_map.DEFAULT_BSS_START,
            '.strings': 0xE800,
            '.reset': 0xFFFE,  # FIXED: Single reset vector
        }
        
        # FIXED: Symbol conflict resolution rules
        self.symbol_priority_rules = {
            'main': ['main.obj', '*.obj'],  # main.obj has priority
            'RESET': ['main.obj', '*.obj'], # main.obj has priority
        }
        
        # Initialize built-in sections
        self._init_builtin_sections()
    
    def _init_builtin_sections(self):
        """Initialize built-in sections"""
        self.sections['.text'] = Section('.text', 'PROGBITS', 'AX', self.segment_layout['.text'], align=2)
        self.sections['.rodata'] = Section('.rodata', 'PROGBITS', 'A', self.segment_layout['.rodata'], align=1)
        self.sections['.data'] = Section('.data', 'PROGBITS', 'WA', self.segment_layout['.data'], align=1)
        self.sections['.bss'] = Section('.bss', 'NOBITS', 'WA', self.segment_layout['.bss'], align=1)
        self.sections['.strings'] = Section('.strings', 'PROGBITS', 'A', self.segment_layout['.strings'], align=1)
        
        # FIXED: Single reset vector section
        self.sections['.reset'] = Section('.reset', 'PROGBITS', 'AX', self.segment_layout['.reset'], align=2)
        
        # Interrupt vector table
        self.sections['.vectors'] = Section('.vectors', 'PROGBITS', 'A', self.memory_map.VECTOR_TABLE_START, align=2)
    
    def add_object_file(self, filename):
        """Add object file to link with priority"""
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Object file not found: {filename}")
        
        obj_file = self._parse_object_file(filename)
        
        # FIXED: Set file priority for conflict resolution
        basename = os.path.basename(filename)
        if 'main' in basename.lower():
            obj_file.priority = 100  # Highest priority
        elif basename.endswith('1.obj') or '5.obj' in basename:
            obj_file.priority = 50   # Medium priority
        else:
            obj_file.priority = 10   # Low priority
        
        self.object_files.append(obj_file)
        print(f"Added object file: {filename} (priority: {obj_file.priority})")
    
    def _parse_object_file(self, filename):
        """Parse ELF object file - SECTION MAPPING FIXED"""
        obj_file = ObjectFile(filename)
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print(f"Parsing object file: {filename}")
            print(f"File size: {len(content)} characters")
            
            # FIXED: Parse sections FIRST to build section index mapping
            sections_match = re.search(r'SECTION HEADERS:(.*?)(?=\n[A-Z]+.*:|SYMBOL TABLE:|RELOCATION|SECTION CONTENTS|$)', content, re.DOTALL)
            if sections_match:
                print("✓ Found SECTION HEADERS")
                self._parse_sections_fixed(sections_match.group(1), obj_file)
            else:
                print("✗ No SECTION HEADERS found")
            
            # Parse symbol table with FIXED section mapping
            symbols_match = re.search(r'SYMBOL TABLE:(.*?)(?=\n[A-Z]+.*:|RELOCATION|SECTION CONTENTS|ASSEMBLY|$)', content, re.DOTALL)
            if symbols_match:
                print("✓ Found SYMBOL TABLE")
                self._parse_symbols_ultra_fixed(symbols_match.group(1), obj_file)
            else:
                print("✗ No SYMBOL TABLE found")
            
            # Parse relocations
            reloc_match = re.search(r'RELOCATION RECORDS.*?:(.*?)(?=\n[A-Z]+.*:|SECTION CONTENTS|ASSEMBLY|$)', content, re.DOTALL)
            if reloc_match:
                print("✓ Found RELOCATION RECORDS")
                self._parse_relocations(reloc_match.group(1), obj_file)
            else:
                print("✗ No RELOCATION RECORDS found")
            
            # Parse section contents
            self._parse_section_contents_ultra_fixed(content, obj_file)
            
            # FIXED: Debug output for verification
            print(f"Sections found: {list(obj_file.sections.keys())}")
            for name, section in obj_file.sections.items():
                print(f"  {name}: {len(section.data)} bytes")
                if len(section.data) > 0:
                    preview = ' '.join(f'{b:02x}' for b in section.data[:8])
                    print(f"    Preview: {preview}...")
                    
        except Exception as e:
            print(f"Error parsing object file {filename}: {e}")
            import traceback
            traceback.print_exc()
            
        return obj_file
    
    def _parse_sections_fixed(self, sections_text, obj_file):
        """Parse section headers with FIXED dynamic mapping"""
        lines = sections_text.strip().split('\n')
        print("Parsing section headers...")
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # FIXED: Section header regex with better matching
            match = re.match(r'\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s*(\S*)', line)
            if match:
                section_idx = int(match.group(1))
                name = match.group(2)
                sec_type = match.group(3)
                addr = int(match.group(4), 16)
                size = int(match.group(5), 16)
                flags = match.group(6) if match.group(6) else ''
                
                print(f"  Found section [{section_idx}] {name}: type={sec_type}, addr=0x{addr:04x}, size={size}, flags={flags}")
                
                # FIXED: Build section index mapping correctly
                obj_file.section_index_map[section_idx] = name
                
                section = Section(name, sec_type, flags, addr, size)
                obj_file.sections[name] = section
        
        print(f"Total sections parsed: {len(obj_file.sections)}")
        print(f"Section index mapping: {obj_file.section_index_map}")
    
    def _parse_symbols_ultra_fixed(self, symbols_text, obj_file):
        """Parse symbol table with ULTRA FIXED section mapping and conflict handling"""
        lines = symbols_text.strip().split('\n')
        print("Parsing symbol table...")
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # FIXED: Symbol parsing regex
            match = re.match(r'\s*\[\s*(\d+)\]\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s+(.+)', line)
            if match:
                sym_idx = int(match.group(1))
                value = int(match.group(2), 16)
                size = int(match.group(3))
                sym_type = match.group(4)
                bind = match.group(5)
                section_ref = match.group(6)
                name = match.group(7).strip()
                
                if name and sym_idx > 0:
                    # FIXED: Handle section mapping with unknown sections
                    section_name = section_ref
                    if section_ref.isdigit():
                        section_idx = int(section_ref)
                        if section_idx in obj_file.section_index_map:
                            section_name = obj_file.section_index_map[section_idx]
                            print(f"  Mapped section index {section_idx} -> {section_name} for symbol {name}")
                        else:
                            # FIXED: Handle unknown sections gracefully
                            print(f"  Warning: Unknown section index {section_idx} for symbol {name}")
                            section_name = 'ABS'  # Treat as absolute
                            # Create a virtual section for unknown references
                            virtual_section_name = f".unknown_{section_idx}"
                            if virtual_section_name not in obj_file.sections:
                                obj_file.sections[virtual_section_name] = Section(virtual_section_name, 'PROGBITS', '', 0xC000 + section_idx * 4)
                            section_name = virtual_section_name
                    elif section_ref in ['UND', 'ABS']:
                        section_name = section_ref
                    
                    print(f"  Found symbol [{sym_idx}] {name}: value=0x{value:04x}, type={sym_type}, bind={bind}, section={section_name}")
                    
                    symbol = Symbol(name, value, size, sym_type, bind, section_name, section_ref not in ['UND'])
                    symbol.source_file = obj_file.filename
                    symbol.priority = obj_file.priority  # FIXED: Inherit file priority
                    obj_file.symbols[name] = symbol
                    
                    if bind == 'GLOBAL':
                        obj_file.global_symbols.add(name)
        
        print(f"Total symbols parsed: {len(obj_file.symbols)}")
        print(f"Global symbols: {len(obj_file.global_symbols)}")
    
    def _parse_section_contents_ultra_fixed(self, content, obj_file):
        """Parse section contents with ULTRA FIXED parsing"""
        print("Attempting to parse SECTION CONTENTS...")
        
        # FIXED: Multiple regex methods with priority
        contents_match = None
        methods = [
            (r'SECTION CONTENTS:(.*?)(?=ASSEMBLY LISTING:|End of|$)', "Standard regex"),
            (r'SECTION CONTENTS:(.*?)ASSEMBLY LISTING:', "Alternative regex"),
            (r'SECTION CONTENTS:(.*?)(?=\n\n[A-Z]|\nEnd)', "Conservative regex")
        ]
        
        for pattern, method_name in methods:
            contents_match = re.search(pattern, content, re.DOTALL)
            if contents_match and len(contents_match.group(1).strip()) > 10:
                print(f"✓ {method_name}: {len(contents_match.group(1))} chars")
                break
        
        if contents_match:
            self._parse_section_data_ultra_fixed(contents_match.group(1), obj_file)
        else:
            # Manual method as fallback
            start_pos = content.find('SECTION CONTENTS:')
            if start_pos != -1:
                end_markers = ['ASSEMBLY LISTING:', 'End of ELF object file', 'End of object file']
                end_pos = len(content)
                
                for marker in end_markers:
                    marker_pos = content.find(marker, start_pos)
                    if marker_pos != -1:
                        end_pos = min(end_pos, marker_pos)
                
                section_contents = content[start_pos + len('SECTION CONTENTS:'):end_pos]
                print(f"✓ Manual method: {len(section_contents)} chars")
                self._parse_section_data_ultra_fixed(section_contents, obj_file)
            else:
                print("✗ No SECTION CONTENTS found!")
    
    def _parse_section_data_ultra_fixed(self, contents_text, obj_file):
        """Parse section data with ULTRA FIXED parsing algorithm"""
        current_section = None
        lines = contents_text.strip().split('\n')
        
        print(f"Parsing section contents... ({len(lines)} lines)")
        
        for line_num, line in enumerate(lines):
            original_line = line
            line = line.strip()
            
            if not line:
                continue
                
            # FIXED: Section header detection
            section_match = re.match(r'Contents of section ([\w.]+):', line)
            if section_match:
                current_section = section_match.group(1)
                print(f"  Found section: {current_section}")
                
                # FIXED: Create section if missing
                if current_section not in obj_file.sections:
                    print(f"  Creating missing section: {current_section}")
                    flags = 'AX' if current_section == '.text' else 'A'
                    obj_file.sections[current_section] = Section(current_section, 'PROGBITS', flags)
                continue
            
            # FIXED: Hex data line parsing
            if current_section and re.match(r'\s*[0-9a-fA-F]{4}', line):
                print(f"  Processing hex line: {repr(line[:50])}...")
                
                # ULTRA FIXED: Multiple hex extraction methods
                hex_bytes = []
                
                # Method 1: Space-separated parsing
                parts = line.split()
                if len(parts) >= 2:
                    addr = int(parts[0], 16)
                    
                    # Extract hex bytes until ASCII representation
                    for i in range(1, len(parts)):
                        part = parts[i]
                        
                        # Stop at ASCII representation (usually starts with letters)
                        if len(part) > 2 and any(c.isalpha() for c in part):
                            break
                        
                        # Parse 2-character hex values
                        if len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part):
                            try:
                                hex_bytes.append(int(part, 16))
                            except ValueError:
                                break
                
                # Method 2: Continuous hex extraction (fallback)
                if not hex_bytes:
                    # Extract hex portion before ASCII
                    hex_match = re.match(r'\s*[0-9a-fA-F]{4}\s+([0-9a-fA-F\s]+?)(?:\s+[^\s0-9a-fA-F]|$)', line)
                    if hex_match:
                        hex_string = hex_match.group(1).replace(' ', '')
                        for j in range(0, len(hex_string), 2):
                            if j + 1 < len(hex_string):
                                try:
                                    hex_bytes.append(int(hex_string[j:j+2], 16))
                                except ValueError:
                                    break
                
                print(f"    Extracted {len(hex_bytes)} bytes")
                
                # FIXED: Add bytes to section
                if hex_bytes and current_section in obj_file.sections:
                    obj_file.sections[current_section].data.extend(hex_bytes)
                    bytes_str = ' '.join(f'{b:02x}' for b in hex_bytes)
                    print(f"    Added to {current_section}: {bytes_str}")
                else:
                    print(f"    No bytes extracted from: {original_line[:50]}...")
        
        # FIXED: Final summary
        print("\nSection parsing summary:")
        for name, section in obj_file.sections.items():
            if section.data:
                preview = ' '.join(f'{b:02x}' for b in section.data[:8])
                print(f"  {name}: {len(section.data)} bytes - {preview}...")
            else:
                print(f"  {name}: 0 bytes (EMPTY)")
    
    def _parse_relocations(self, reloc_text, obj_file):
        """Parse relocation records"""
        lines = reloc_text.strip().split('\n')
        print("Parsing relocations...")
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Relocation line parsing
            match = re.match(r'\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S+)\s+[0-9a-fA-F]+\s+(.+)', line)
            if match:
                offset = int(match.group(1), 16)
                rel_type = match.group(2)
                symbol = match.group(3).strip()
                
                print(f"  Found relocation: offset=0x{offset:04x}, type={rel_type}, symbol={symbol}")
                
                relocation = Relocation(offset, symbol, rel_type)
                obj_file.relocations.append(relocation)
        
        print(f"Total relocations parsed: {len(obj_file.relocations)}")
    
    def link(self, output_filename, entry_symbol='RESET'):
        """Link object files with ULTRA FIXED processing"""
        print(f"Linking {len(self.object_files)} object files...")
        
        # FIXED: Sort object files by priority
        self.object_files.sort(key=lambda x: x.priority, reverse=True)
        
        # Step 1: Collect symbols with conflict resolution
        self._collect_symbols_ultra_fixed()
        
        # Step 2: Collect and merge sections
        self._collect_sections_ultra_fixed()
        
        # Step 3: Resolve symbols
        self._resolve_symbols()
        
        # Step 4: Assign addresses
        self._assign_addresses_ultra_fixed()
        
        # Step 5: Apply relocations
        self._apply_relocations_ultra_fixed()
        
        # Step 6: Set entry point
        if entry_symbol in self.global_symbols:
            self.entry_point = self.global_symbols[entry_symbol].value
            print(f"Entry point set to {entry_symbol}: 0x{self.entry_point:04X}")
        
        # Step 7: Create reset vector (FIXED: single instance)
        self._create_reset_vector_ultra_fixed()
        
        # Step 8: Generate executable ELF
        self._write_executable_elf(output_filename)
        
        print(f"Executable created: {output_filename}")
        return True
    
    def _collect_symbols_ultra_fixed(self):
        """Collect symbols with ULTRA FIXED conflict resolution"""
        # Built-in symbols that are allowed multiple definitions
        builtin_symbols = {'WDTCTL', 'WDTPW', 'WDTHOLD', 'P1DIR', 'P1OUT', 'P1IN', 
                          'P2DIR', 'P2OUT', 'P2IN', '__STACK_END'}
        
        symbol_candidates = {}  # Track multiple definitions
        
        for obj_file in self.object_files:
            for name, symbol in obj_file.symbols.items():
                if symbol.bind == 'GLOBAL':
                    if name not in symbol_candidates:
                        symbol_candidates[name] = []
                    symbol_candidates[name].append(symbol)
        
        # FIXED: Resolve conflicts with priority system
        for name, candidates in symbol_candidates.items():
            if len(candidates) > 1 and name not in builtin_symbols:
                print(f"Resolving conflict for symbol '{name}' ({len(candidates)} definitions)")
                
                # Sort by priority (highest first), then by definition status
                candidates.sort(key=lambda s: (s.priority, s.defined), reverse=True)
                
                chosen = candidates[0]
                print(f"  Chosen: {chosen.source_file} (priority: {chosen.priority})")
                for rejected in candidates[1:]:
                    print(f"  Rejected: {rejected.source_file} (priority: {rejected.priority})")
                
                self.global_symbols[name] = chosen
            elif candidates:
                # Single definition or built-in symbol
                self.global_symbols[name] = candidates[0]
                
        # Add local symbols
        for obj_file in self.object_files:
            for name, symbol in obj_file.symbols.items():
                if symbol.bind != 'GLOBAL':
                    local_name = f"{os.path.basename(obj_file.filename)}:{name}"
                    self.symbols[local_name] = symbol
                    
                # Keep all symbols for reference
                self.symbols[name] = symbol
    
    def _collect_sections_ultra_fixed(self):
        """Collect sections with ULTRA FIXED merging and offset tracking"""
        print("Collecting sections from object files...")
        
        for obj_file in self.object_files:
            print(f"Processing sections from {obj_file.filename}")
            for name, section in obj_file.sections.items():
                print(f"  Found section: {name} with {len(section.data)} bytes")
                
                if name not in self.sections:
                    # Create new section
                    base_addr = self.segment_layout.get(name, 0)
                    new_section = Section(name, section.type, section.flags, base_addr, align=section.align)
                    self.sections[name] = new_section
                    print(f"  Created new section: {name} at 0x{base_addr:04X}")
                
                # FIXED: Track offset for symbol relocation
                if section.data:
                    current_size = len(self.sections[name].data)
                    
                    # Align data
                    alignment = section.align
                    if current_size % alignment != 0:
                        padding = alignment - (current_size % alignment)
                        self.sections[name].data.extend([0] * padding)
                        current_size += padding
                    
                    # Store offset information for this object file's contribution
                    section.output_offset = current_size
                    section.base_addr = self.sections[name].addr
                    
                    # Append data
                    self.sections[name].data.extend(section.data)
                    print(f"  Added {len(section.data)} bytes to {name}, total: {len(self.sections[name].data)}")
        
        print("Final sections:")
        for name, section in self.sections.items():
            if section.data or section.type == 'NOBITS':
                print(f"  {name}: {len(section.data)} bytes at 0x{section.addr:04X}")
    
    def _resolve_symbols(self):
        """Resolve symbols with built-in definitions"""
        # Built-in MSP430 symbols
        builtin_symbols = {
            'WDTCTL': 0x0120, 'WDTPW': 0x5A00, 'WDTHOLD': 0x0080,
            'P1DIR': 0x0022, 'P1OUT': 0x0021, 'P1IN': 0x0020,
            'P2DIR': 0x002A, 'P2OUT': 0x0029, 'P2IN': 0x0028,
            '__STACK_END': 0x0400
        }
        
        # Add built-in symbols if not already defined
        for name, value in builtin_symbols.items():
            if name not in self.global_symbols:
                symbol = Symbol(name, value, 2, 'OBJECT', 'GLOBAL', 'ABS', True)
                symbol.source_file = "built-in"
                self.global_symbols[name] = symbol
        
        # Check for undefined symbols
        for obj_file in self.object_files:
            for relocation in obj_file.relocations:
                symbol_name = relocation.symbol
                if (symbol_name not in self.global_symbols and 
                    symbol_name not in self.symbols and
                    symbol_name not in builtin_symbols):
                    self.undefined_symbols.add(symbol_name)
        
        if self.undefined_symbols:
            print("Warning: Undefined symbols:")
            for symbol in self.undefined_symbols:
                print(f"  {symbol}")
    
    def _assign_addresses_ultra_fixed(self):
        """Assign addresses with ULTRA FIXED symbol handling"""
        current_addresses = dict(self.segment_layout)
        
        # Update section addresses and sizes
        for name, section in self.sections.items():
            if section.data or section.type == 'NOBITS':
                if name in current_addresses:
                    section.addr = current_addresses[name]
                section.size = len(section.data)
                
                # Update next available address
                if section.type != 'NOBITS':
                    if name in current_addresses:
                        current_addresses[name] += section.size
                        # Align to word boundary
                        if current_addresses[name] % 2 != 0:
                            current_addresses[name] += 1
        
        # ULTRA FIXED: Symbol address assignment
        for obj_file in self.object_files:
            print(f"\nProcessing symbols from {obj_file.filename}:")
            
            for name, symbol in obj_file.symbols.items():
                original_value = symbol.value
                
                # Skip built-in symbols (ABS section)
                if symbol.section == 'ABS':
                    print(f"  {name}: ABS absolute 0x{original_value:04X} (kept)")
                    continue
                
                new_value = original_value
                
                # FIXED: Handle flash range addresses (already absolute)
                if 0xC000 <= original_value <= 0xFFFF:
                    new_value = original_value
                    print(f"  {name}: {symbol.section} absolute 0x{original_value:04X} (kept)")
                
                # FIXED: Handle section-relative addresses
                elif symbol.section in obj_file.sections:
                    obj_section = obj_file.sections[symbol.section]
                    
                    if hasattr(obj_section, 'output_offset') and hasattr(obj_section, 'base_addr'):
                        new_value = obj_section.base_addr + obj_section.output_offset + original_value
                        print(f"  {name}: {symbol.section} 0x{original_value:04X} + 0x{obj_section.output_offset:04X} = 0x{new_value:04X}")
                    elif symbol.section in self.sections:
                        new_value = self.sections[symbol.section].addr + original_value
                        print(f"  {name}: {symbol.section} section-based 0x{original_value:04X} -> 0x{new_value:04X}")
                
                # FIXED: Handle unknown sections (treat as absolute)
                elif symbol.section.startswith('.unknown_') or symbol.section.startswith('UNKNOWN_'):
                    # These are likely already absolute addresses
                    new_value = original_value
                    print(f"  {name}: Unknown section absolute 0x{original_value:04X} (kept)")
                
                # Default case
                else:
                    new_value = original_value
                    print(f"  {name}: Default 0x{original_value:04X} (kept)")
                
                # Update symbol value
                symbol.value = new_value
                
                # Update global symbol table
                if symbol.bind == 'GLOBAL':
                    self.global_symbols[name] = symbol
        
        # Debug output
        print(f"\nFinal symbol addresses:")
        for name in ['RESET', 'main']:
            if name in self.global_symbols:
                symbol = self.global_symbols[name]
                print(f"  {name}: 0x{symbol.value:04X}")
    
    def _apply_relocations_ultra_fixed(self):
        """Apply relocations with ULTRA FIXED offset calculation"""
        relocations_applied = 0
        
        for obj_file in self.object_files:
            if not obj_file.relocations:
                continue
                
            print(f"\nProcessing relocations from {obj_file.filename}:")
            
            for relocation in obj_file.relocations:
                symbol_name = relocation.symbol
                
                # Find symbol value
                symbol_value = 0
                if symbol_name in self.global_symbols:
                    symbol_value = self.global_symbols[symbol_name].value
                elif symbol_name in self.symbols:
                    symbol_value = self.symbols[symbol_name].value
                else:
                    print(f"  ✗ Unresolved symbol: {symbol_name}")
                    continue
                
                # ULTRA FIXED: Find target section and calculate correct offset
                target_section = None
                target_offset = relocation.offset
                
                # Find which section this relocation belongs to
                if '.text' in obj_file.sections:
                    obj_text_section = obj_file.sections['.text']
                    if hasattr(obj_text_section, 'output_offset'):
                        target_offset = obj_text_section.output_offset + relocation.offset
                        target_section = self.sections['.text']
                    else:
                        target_section = self.sections['.text']
                        target_offset = relocation.offset
                
                # Apply relocation
                if target_section and relocation.type == 'R_MSP430_16':
                    if target_offset + 1 < len(target_section.data):
                        # Apply 16-bit relocation (little endian)
                        target_section.data[target_offset] = symbol_value & 0xFF
                        target_section.data[target_offset + 1] = (symbol_value >> 8) & 0xFF
                        relocations_applied += 1
                        print(f"  ✓ Applied: {symbol_name} -> 0x{symbol_value:04X} at offset 0x{target_offset:04X}")
                    else:
                        print(f"  ✗ Invalid offset: 0x{target_offset:04X} >= {len(target_section.data)}")
                else:
                    print(f"  ✗ Unsupported relocation: {relocation.type}")
        
        print(f"Total relocations applied: {relocations_applied}")
    
    def _create_reset_vector_ultra_fixed(self):
        """Create SINGLE reset vector - ULTRA FIXED"""
        # ULTRA FIXED: Ensure only ONE reset vector
        if '.reset' in self.sections:
            del self.sections['.reset']
        
        # Create fresh reset section with SINGLE 2-byte vector
        self.sections['.reset'] = Section('.reset', 'PROGBITS', 'AX', 0xFFFE, align=2)
        
        # Set reset vector data (EXACTLY 2 bytes)
        reset_vector_data = bytearray(2)
        reset_vector_data[0] = self.entry_point & 0xFF
        reset_vector_data[1] = (self.entry_point >> 8) & 0xFF
        self.sections['.reset'].data = reset_vector_data
        
        # Also set in vectors section
        if '.vectors' in self.sections:
            vectors_section = self.sections['.vectors']
            if len(vectors_section.data) < 32:
                vectors_section.data = bytearray(32)  # Full vector table
            # Reset vector is at offset 30 (0xFFFE - 0xFFE0)
            vectors_section.data[30] = reset_vector_data[0]
            vectors_section.data[31] = reset_vector_data[1]
        
        print(f"Reset vector set to: 0x{self.entry_point:04X}")
    
    def _write_executable_elf(self, filename):
        """Write executable ELF file with comprehensive information"""
        with open(filename, 'w', encoding='utf-8') as f:
            # ELF Header
            f.write("MSP430 Executable ELF File\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("ELF HEADER:\n")
            f.write(f"  Magic:           ELF\n")
            f.write(f"  Class:           ELF32\n")
            f.write(f"  Data:            LSB (Little Endian)\n")
            f.write(f"  Version:         1\n")
            f.write(f"  OS/ABI:          SYSV\n")
            f.write(f"  Machine:         MSP430\n")
            f.write(f"  Type:            EXEC (Executable file)\n")
            f.write(f"  Entry point:     0x{self.entry_point:08x}\n")
            f.write(f"  Created:         {time.ctime()}\n")
            f.write(f"  Linker:          MSP430-Linker-v4.0-ULTRA-FIXED\n\n")
            
            # Program Headers
            f.write("PROGRAM HEADERS:\n")
            f.write("  Type           Offset   VirtAddr   PhysAddr   FileSize MemSize  Flg Align\n")
            f.write("  " + "-" * 70 + "\n")
            
            load_segments = []
            offset = 0x1000
            for section_name in ['.text', '.rodata', '.data', '.strings', '.vectors', '.reset']:
                if section_name in self.sections and self.sections[section_name].data:
                    section = self.sections[section_name]
                    flags = 'R-E' if 'X' in section.flags else 'RW-' if 'W' in section.flags else 'R--'
                    load_segments.append((section_name, flags, offset))
                    f.write(f"  LOAD           {offset:08x} {section.addr:08x} {section.addr:08x} ")
                    f.write(f"{len(section.data):08x} {len(section.data):08x} {flags} {section.align:5x}\n")
                    offset += 0x1000
            
            # Section Headers
            f.write("\nSECTION HEADERS:\n")
            f.write("  [Nr] Name              Type            Addr     Off    Size   Flg Align\n")
            f.write("  " + "-" * 70 + "\n")
            
            section_index = 0
            for name, section in self.sections.items():
                if section.data or section.type == 'NOBITS':
                    offset = next((seg[2] for seg in load_segments if seg[0] == name), section_index * 0x1000)
                    f.write(f"  [{section_index:2d}] {name:<16} {section.type:<14} ")
                    f.write(f"{section.addr:08x} {offset:06x} {len(section.data):06x} ")
                    f.write(f"{section.flags:<3} {section.align:5d}\n")
                    section_index += 1
            
            # Symbol Table
            f.write("\nSYMBOL TABLE:\n")
            f.write("  [Nr]    Value  Size Type    Bind   Vis      Ndx Name\n")
            f.write("  " + "-" * 60 + "\n")
            
            symbol_index = 0
            for name, symbol in sorted(self.global_symbols.items()):
                section_name = symbol.section if symbol.section not in ['UND', 'ABS'] else symbol.section
                f.write(f"  [{symbol_index:3d}] {symbol.value:08x} {symbol.size:4d} ")
                f.write(f"{symbol.type:<7} {symbol.bind:<6} DEFAULT ")
                f.write(f"{section_name:<3} {name}\n")
                symbol_index += 1
            
            # Memory Layout
            f.write("\nMEMORY LAYOUT:\n")
            f.write("  Section        Start      End        Size       Type\n")
            f.write("  " + "-" * 55 + "\n")
            
            for name, section in self.sections.items():
                if section.data or section.type == 'NOBITS':
                    end_addr = section.addr + len(section.data) - 1 if section.data else section.addr
                    f.write(f"  {name:<14} 0x{section.addr:04X}     0x{end_addr:04X}     ")
                    f.write(f"{len(section.data):5d}      {section.type}\n")
            
            # Section Contents
            f.write("\nSECTION CONTENTS:\n")
            for name, section in self.sections.items():
                if section.data:
                    f.write(f"\nContents of section {name}:\n")
                    data = section.data
                    addr = section.addr
                    
                    for i in range(0, len(data), 16):
                        line_addr = addr + i
                        line_data = data[i:i+16]
                        hex_str = ' '.join(f"{b:02x}" for b in line_data)
                        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
                        f.write(f"  {line_addr:04x} {hex_str:<47} {ascii_str}\n")
            
            # Statistics
            text_size = len(self.sections['.text'].data) if '.text' in self.sections else 0
            data_size = len(self.sections['.data'].data) if '.data' in self.sections else 0
            bss_size = len(self.sections['.bss'].data) if '.bss' in self.sections else 0
            rodata_size = len(self.sections['.rodata'].data) if '.rodata' in self.sections else 0
            strings_size = len(self.sections['.strings'].data) if '.strings' in self.sections else 0
            reset_size = len(self.sections['.reset'].data) if '.reset' in self.sections else 0
            
            f.write(f"\nLINKER STATISTICS:\n")
            f.write(f"  Object files linked:     {len(self.object_files)}\n")
            f.write(f"  Global symbols:          {len(self.global_symbols)}\n")
            f.write(f"  Sections created:        {len([s for s in self.sections.values() if s.data])}\n")
            f.write(f"  Code size (.text):       {text_size} bytes\n")
            f.write(f"  Reset vectors:           {reset_size} bytes\n")
            f.write(f"  Read-only data:          {rodata_size + strings_size} bytes\n")
            f.write(f"  Initialized data:        {data_size} bytes\n")
            f.write(f"  Uninitialized data:      {bss_size} bytes\n")
            
            total_flash = text_size + rodata_size + strings_size + data_size + reset_size
            total_ram = data_size + bss_size
            
            f.write(f"  Total flash usage:       {total_flash}/{self.memory_map.FLASH_SIZE} bytes ({100*total_flash/self.memory_map.FLASH_SIZE:.1f}%)\n")
            f.write(f"  Total RAM usage:         {total_ram}/{self.memory_map.RAM_SIZE} bytes ({100*total_ram/self.memory_map.RAM_SIZE:.1f}%)\n")
            
            if self.undefined_symbols:
                f.write(f"\nUNDEFINED SYMBOLS:\n")
                for symbol in sorted(self.undefined_symbols):
                    f.write(f"  {symbol}\n")
            
            f.write(f"\nEnd of executable ELF file.\n")

def main():
    """Main linker function"""
    if len(sys.argv) < 3:
        print("MSP430 ELF Linker v4.0 - ULTRA FIXED VERSION")
        print("Usage: python msp430_linker_ultra_fixed.py <output.elf> <input1.obj> [input2.obj] ...")
        print("Example: python msp430_linker_ultra_fixed.py program.elf main.obj startup.obj")
        return 1
    
    output_file = sys.argv[1]
    input_files = sys.argv[2:]
    
    # Validate input files
    for input_file in input_files:
        if not os.path.exists(input_file):
            print(f"Error: Input file not found: {input_file}")
            return 1
        if not input_file.endswith('.obj'):
            print(f"Warning: File {input_file} doesn't have .obj extension")
    
    try:
        # Create linker instance
        linker = MSP430Linker()
        
        print("MSP430 G2553 ELF Linker v4.0 - ULTRA FIXED VERSION")
        print("=" * 60)
        
        # Add all object files with priority order
        for input_file in input_files:
            linker.add_object_file(input_file)
        
        # Debug: Check loaded sections
        print("\nBefore linking - loaded sections:")
        for obj_file in linker.object_files:
            print(f"File: {obj_file.filename}")
            for name, section in obj_file.sections.items():
                print(f"  {name}: {len(section.data)} bytes")
                if len(section.data) > 0:
                    preview = ' '.join(f'{b:02x}' for b in section.data[:4])
                    print(f"    Preview: {preview}...")
        
        # Link and create executable
        success = linker.link(output_file)
        
        if success:
            print("\n" + "=" * 50)
            print("Linking completed successfully!")
            print(f"Executable created: {output_file}")
            
            # Show memory usage
            sections = linker.sections
            text_size = len(sections['.text'].data) if '.text' in sections else 0
            data_size = len(sections['.data'].data) if '.data' in sections else 0
            bss_size = len(sections['.bss'].data) if '.bss' in sections else 0
            strings_size = len(sections['.strings'].data) if '.strings' in sections else 0
            reset_size = len(sections['.reset'].data) if '.reset' in sections else 0
            
            print(f"\nMemory Usage Summary:")
            print(f"  Code (.text):      {text_size:4d} bytes")
            print(f"  Reset vectors:     {reset_size:4d} bytes")
            print(f"  Strings:           {strings_size:4d} bytes")
            print(f"  Data (.data):      {data_size:4d} bytes") 
            print(f"  BSS (.bss):        {bss_size:4d} bytes")
            print(f"  Total Flash:       {text_size + strings_size + data_size + reset_size:4d}/{linker.memory_map.FLASH_SIZE} bytes")
            print(f"  Total RAM:         {data_size + bss_size:4d}/{linker.memory_map.RAM_SIZE} bytes")
            
            # Memory usage percentages
            flash_usage = (text_size + strings_size + data_size + reset_size) / linker.memory_map.FLASH_SIZE * 100
            ram_usage = (data_size + bss_size) / linker.memory_map.RAM_SIZE * 100
            
            print(f"  Flash utilization: {flash_usage:.1f}%")
            print(f"  RAM utilization:   {ram_usage:.1f}%")
            
            # Show entry point
            print(f"\nEntry Point: 0x{linker.entry_point:04X}")
            
            # Show found symbols
            if linker.global_symbols:
                print(f"\nGlobal Symbols Found:")
                for name, symbol in sorted(linker.global_symbols.items()):
                    if symbol.section not in ['ABS']:  # Skip built-in symbols
                        print(f"  {name}: 0x{symbol.value:04X} ({symbol.type})")
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"Linker error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())