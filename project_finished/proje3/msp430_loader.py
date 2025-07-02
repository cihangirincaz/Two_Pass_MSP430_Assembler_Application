#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSP430 G2553 Loader - Senin toolchain'in için özel tasarlandı
Linker'ın ürettiği .elf dosyasını MSP430 flash memory'sine yükler
"""

import sys
import os
import re
import struct
import time
from collections import OrderedDict

class MSP430FlashMemory:
    """MSP430 Flash Memory Simulation - G2553 için optimize edilmiş"""
    
    def __init__(self):
        # MSP430 G2553 Memory Map (linker'ınla uyumlu)
        self.FLASH_START = 0xC000
        self.FLASH_END = 0xFFFF
        self.FLASH_SIZE = 0x4000  # 16KB
        self.RESET_VECTOR = 0xFFFE
        
        # RAM Memory
        self.RAM_START = 0x0200
        self.RAM_END = 0x03FF
        self.RAM_SIZE = 0x0200    # 512 bytes
        
        # Flash memory simulation (address -> byte)
        self.flash_data = {}
        
        # Memory statistics
        self.used_flash = 0
        self.code_size = 0
        self.data_size = 0
        
        # Section mapping (linker'ından gelen section'lar)
        self.section_map = {
            '.text': self.FLASH_START,       # 0xC000 - kod
            '.rodata': 0xE000,               # Read-only data
            '.data': 0xC400,                 # Flash'te saklanır
            '.bss': self.RAM_START,          # RAM'de
            '.strings': 0xE800,              # String constants
            '.reset': self.RESET_VECTOR,     # 0xFFFE
            '.vectors': 0xFFE0               # Interrupt vectors
        }
        
    def write_byte(self, address, byte_value):
        """Flash'e veya diğer memory'ye byte yaz - FIXED"""
        # MSP430 memory map'ine göre tüm adresleri kabul et
        if (self.FLASH_START <= address <= self.FLASH_END or  # Flash
            self.RAM_START <= address <= self.RAM_END or      # RAM  
            0x0000 <= address <= 0x01FF):                     # SFR + Peripherals
            self.flash_data[address] = byte_value & 0xFF
            return True
        return False
    
    def write_word(self, address, word_value):
        """Flash'e word (16-bit) yaz - Little Endian"""
        low_byte = word_value & 0xFF
        high_byte = (word_value >> 8) & 0xFF
        
        success1 = self.write_byte(address, low_byte)
        success2 = self.write_byte(address + 1, high_byte)
        return success1 and success2
    
    def read_byte(self, address):
        """Flash'ten byte oku"""
        return self.flash_data.get(address, 0xFF)  # Erased flash = 0xFF
    
    def read_word(self, address):
        """Flash'ten word oku - Little Endian"""
        low_byte = self.read_byte(address)
        high_byte = self.read_byte(address + 1)
        return low_byte | (high_byte << 8)
    
    def erase_flash(self):
        """Flash'i temizle (erase)"""
        self.flash_data.clear()
        self.used_flash = 0
        self.code_size = 0
        self.data_size = 0
    
    def get_memory_segments(self):
        """Kullanılan memory segmentlerini döndür"""
        if not self.flash_data:
            return []
        
        addresses = sorted(self.flash_data.keys())
        segments = []
        
        current_start = addresses[0]
        current_end = addresses[0]
        
        for addr in addresses[1:]:
            if addr == current_end + 1:
                current_end = addr
            else:
                segments.append((current_start, current_end))
                current_start = addr
                current_end = addr
        
        segments.append((current_start, current_end))
        return segments
    
    def get_usage_stats(self):
        """Flash kullanım istatistikleri"""
        used_addresses = len(self.flash_data)
        usage_percent = (used_addresses / self.FLASH_SIZE) * 100
        
        return {
            'used_bytes': used_addresses,
            'total_bytes': self.FLASH_SIZE,
            'usage_percent': usage_percent,
            'code_size': self.code_size,
            'data_size': self.data_size
        }

class MSP430Loader:
    """MSP430 ELF Loader - Senin assembler/linker toolchain'i için"""
    
    def __init__(self):
        self.flash = MSP430FlashMemory()
        self.sections = {}
        self.symbols = {}
        self.entry_point = 0xC000
        self.loaded_sections = []
        self.elf_header = {}
        
    def load_elf_executable(self, elf_filename):
        """Linker'ından gelen ELF executable dosyasını yükle"""
        print(f"Loading ELF executable: {elf_filename}")
        
        if not os.path.exists(elf_filename):
            print(f"Error: ELF file not found: {elf_filename}")
            return False
        
        try:
            # ELF dosyasını parse et
            success = self._parse_elf_file(elf_filename)
            if not success:
                return False
            
            # Flash'i temizle
            self.flash.erase_flash()
            
            # Section'ları flash'e yükle
            self._load_sections_to_flash()
            
            # Entry point'i ayarla
            self._set_entry_point()
            
            # Reset vector'ü ayarla
            self._set_reset_vector()
            
            # Yükleme başarılı
            print("ELF executable loaded successfully!")
            self._print_load_summary()
            
            return True
            
        except Exception as e:
            print(f"Error loading ELF executable: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _parse_elf_file(self, filename):
        """Senin linker formatına uygun ELF dosyasını parse et"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print("Parsing ELF executable...")
            
            # ELF Header'ı parse et
            self._parse_elf_header(content)
            
            # Entry point'i bul
            entry_match = re.search(r'Entry point:\s+0x([0-9a-fA-F]+)', content)
            if entry_match:
                self.entry_point = int(entry_match.group(1), 16)
                print(f"Found entry point: 0x{self.entry_point:04X}")
            
            # Section'ları parse et
            self._parse_sections(content)
            
            # Symbol'ları parse et
            self._parse_symbols(content)
            
            return True
            
        except Exception as e:
            print(f"Error parsing ELF file: {e}")
            return False
    
    def _parse_elf_header(self, content):
        """ELF Header bilgilerini parse et"""
        header_match = re.search(r'ELF HEADER:(.*?)(?=\n[A-Z ]+:|PROGRAM HEADERS|$)', content, re.DOTALL)
        if not header_match:
            return
        
        header_text = header_match.group(1)
        
        # Header bilgilerini çıkar
        patterns = {
            'magic': r'Magic:\s+(.+)',
            'class': r'Class:\s+(.+)',
            'data': r'Data:\s+(.+)',
            'machine': r'Machine:\s+(.+)',
            'type': r'Type:\s+(.+)',
            'linker': r'Linker:\s+(.+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, header_text)
            if match:
                self.elf_header[key] = match.group(1).strip()
        
        print(f"ELF Header parsed: {self.elf_header.get('type', 'Unknown')} for {self.elf_header.get('machine', 'MSP430')}")
    
    def _parse_sections(self, content):
        """Section contents'leri parse et"""
        # Önce MEMORY LAYOUT'dan doğru adresleri al
        self._parse_memory_layout(content)
        
        # SECTION CONTENTS kısmını bul
        contents_match = re.search(r'SECTION CONTENTS:(.*?)(?=\nLINKER STATISTICS|End of|$)', content, re.DOTALL)
        if not contents_match:
            print("Warning: No SECTION CONTENTS found")
            return
        
        contents_text = contents_match.group(1)
        current_section = None
        
        print("Parsing section contents...")
        
        for line in contents_text.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Section header: "Contents of section .text:"
            section_match = re.match(r'Contents of section ([\w.]+):', line)
            if section_match:
                current_section = section_match.group(1)
                if current_section not in self.sections:
                    self.sections[current_section] = {
                        'data': [],
                        'base_addr': self.flash.section_map.get(current_section, 0xC000)
                    }
                print(f"  Found section: {current_section} -> 0x{self.sections[current_section]['base_addr']:04X}")
                continue
            
            # Hex data line: "  c000 31 40 00 04 b0 12 34 56 ..."
            if current_section and re.match(r'\s*[0-9a-fA-F]{4}', line):
                self._parse_hex_line(line, current_section)
    
    def _parse_memory_layout(self, content):
        """ELF dosyasındaki MEMORY LAYOUT'dan doğru adresleri al"""
        layout_match = re.search(r'MEMORY LAYOUT:(.*?)(?=\nSECTION CONTENTS|$)', content, re.DOTALL)
        if not layout_match:
            print("Warning: No MEMORY LAYOUT found")
            return
        
        layout_text = layout_match.group(1)
        
        for line in layout_text.split('\n'):
            line = line.strip()
            if not line or line.startswith('Section') or line.startswith('-'):
                continue
            
            # Parse layout line: "  .text          0xC000     0xC0FB       252      PROGBITS"
            match = re.match(r'(\.\w+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\d+)', line)
            if match:
                section_name = match.group(1)
                start_addr = int(match.group(2), 16)
                end_addr = int(match.group(3), 16)
                size = int(match.group(4))
                
                # Section mapping'i güncelle
                self.flash.section_map[section_name] = start_addr
                print(f"  Memory layout: {section_name} -> 0x{start_addr:04X} ({size} bytes)")
    
    def _parse_hex_line(self, line, section_name):
        """Senin linker'ının hex formatını parse et - FIXED"""
        parts = line.split()
        if len(parts) < 2:
            return
        
        try:
            # Address (linker'ından absolute address geliyor)
            absolute_addr = int(parts[0], 16)
            
            # Hex bytes'ları çıkar
            hex_bytes = []
            for i in range(1, len(parts)):
                part = parts[i]
                
                # ASCII representation'a gelene kadar hex parse et
                if len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part):
                    hex_bytes.append(int(part, 16))
                else:
                    break  # ASCII kısmına geldi
            
            # Section'a data ekle (absolute address kullan)
            if hex_bytes:
                for i, byte_val in enumerate(hex_bytes):
                    self.sections[section_name]['data'].append((absolute_addr + i, byte_val))
                
                print(f"    Added {len(hex_bytes)} bytes to {section_name} at 0x{absolute_addr:04X}")
                
        except ValueError as e:
            print(f"    Warning: Could not parse hex line: {line[:50]}... ({e})")
    
    def _parse_symbols(self, content):
        """Symbol table'ı parse et"""
        symbols_match = re.search(r'SYMBOL TABLE:(.*?)(?=\nMEMORY LAYOUT|SECTION CONTENTS|$)', content, re.DOTALL)
        if not symbols_match:
            print("Warning: No SYMBOL TABLE found")
            return
        
        symbols_text = symbols_match.group(1)
        symbol_count = 0
        
        for line in symbols_text.split('\n'):
            line = line.strip()
            if not line or line.startswith('[Nr]') or line.startswith('-'):
                continue
            
            # Symbol line format: [  0] 0000c000    8 FUNC    GLOBAL DEFAULT   1 RESET
            match = re.match(r'\[\s*\d+\]\s+([0-9a-fA-F]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)', line)
            if match:
                value = int(match.group(1), 16)
                name = match.group(2).strip()
                self.symbols[name] = value
                symbol_count += 1
        
        print(f"Parsed {symbol_count} symbols")
    
    def _load_sections_to_flash(self):
        """Section'ları flash memory'ye yükle - FIXED"""
        print("\nLoading sections to flash memory...")
        
        for section_name, section_info in self.sections.items():
            if not section_info['data']:
                continue
            
            print(f"Loading {section_name} section...")
            
            bytes_loaded = 0
            for absolute_addr, byte_value in section_info['data']:
                # Direct absolute address kullan (base_addr ile toplama!)
                if self.flash.write_byte(absolute_addr, byte_value):
                    bytes_loaded += 1
                else:
                    print(f"  Warning: Failed to write to address 0x{absolute_addr:04X}")
            
            # Base address'i ilk byte'ın adresinden al
            if section_info['data']:
                actual_base = min(addr for addr, _ in section_info['data'])
                print(f"  Loaded {bytes_loaded} bytes starting from 0x{actual_base:04X}")
                self.loaded_sections.append({
                    'name': section_name,
                    'base_addr': actual_base,
                    'size': bytes_loaded
                })
                
                # Statistics update
                if section_name == '.text':
                    self.flash.code_size += bytes_loaded
                elif section_name in ['.data', '.rodata', '.strings']:
                    self.flash.data_size += bytes_loaded
    
    def _set_entry_point(self):
        """Entry point'i ayarla"""
        # Symbol table'dan RESET veya main'i bul
        if 'RESET' in self.symbols:
            self.entry_point = self.symbols['RESET']
        elif 'main' in self.symbols:
            self.entry_point = self.symbols['main']
        
        print(f"Entry point set to: 0x{self.entry_point:04X}")
    
    def _set_reset_vector(self):
        """Reset vector'ü flash'e yaz"""
        print(f"Setting reset vector to 0x{self.entry_point:04X}")
        
        # Reset vector MSP430'da 0xFFFE adresinde
        success = self.flash.write_word(self.flash.RESET_VECTOR, self.entry_point)
        if success:
            print("Reset vector programmed successfully")
        else:
            print("Error: Failed to program reset vector")
    
    def _print_load_summary(self):
        """Yükleme özetini yazdır"""
        stats = self.flash.get_usage_stats()
        
        print("\n" + "="*50)
        print("FLASH PROGRAMMING SUMMARY")
        print("="*50)
        
        print(f"Entry Point:      0x{self.entry_point:04X}")
        print(f"Reset Vector:     0x{self.flash.RESET_VECTOR:04X} -> 0x{self.entry_point:04X}")
        
        print(f"\nLoaded Sections:")
        for section in self.loaded_sections:
            print(f"  {section['name']:<12} 0x{section['base_addr']:04X}  {section['size']:4d} bytes")
        
        print(f"\nFlash Memory Usage:")
        print(f"  Code size:        {stats['code_size']:4d} bytes")
        print(f"  Data size:        {stats['data_size']:4d} bytes")
        print(f"  Total used:       {stats['used_bytes']:4d} bytes")
        print(f"  Total available:  {stats['total_bytes']:4d} bytes")
        print(f"  Usage:            {stats['usage_percent']:.1f}%")
        
        # Memory segments
        segments = self.flash.get_memory_segments()
        print(f"\nMemory Segments:")
        for start, end in segments:
            print(f"  0x{start:04X} - 0x{end:04X}  ({end - start + 1} bytes)")
    
    def write_intel_hex(self, hex_filename):
        """Intel HEX formatında dosya oluştur (programlama için)"""
        print(f"Creating Intel HEX file: {hex_filename}")
        
        try:
            with open(hex_filename, 'w') as f:
                # Sort addresses
                addresses = sorted(self.flash.flash_data.keys())
                
                if addresses:
                    # Group consecutive addresses into records
                    self._write_hex_records(f, addresses)
                
                # End of file record
                f.write(":00000001FF\n")
            
            print(f"Intel HEX file created: {hex_filename}")
            return True
            
        except Exception as e:
            print(f"Error creating Intel HEX file: {e}")
            return False
    
    def _write_hex_records(self, f, addresses):
        """Intel HEX record'larını yaz"""
        current_addr = addresses[0]
        current_data = []
        
        for addr in addresses:
            if addr == current_addr + len(current_data):
                # Consecutive address
                current_data.append(self.flash.flash_data[addr])
                
                # Write record if we have 16 bytes or if this is the last address
                if len(current_data) == 16 or addr == addresses[-1]:
                    self._write_single_hex_record(f, current_addr, current_data)
                    current_addr = addr + 1
                    current_data = []
            else:
                # Write current group if any
                if current_data:
                    self._write_single_hex_record(f, current_addr, current_data)
                
                # Start new group
                current_addr = addr
                current_data = [self.flash.flash_data[addr]]
    
    def _write_single_hex_record(self, f, start_addr, data):
        """Tek Intel HEX record yaz"""
        # Record format: :LLAAAATT[DD...]CC
        # LL = data length, AAAA = address, TT = type (00=data)
        record = f":{len(data):02X}{start_addr:04X}00"
        
        checksum = len(data) + (start_addr >> 8) + (start_addr & 0xFF) + 0x00
        
        for byte_val in data:
            record += f"{byte_val:02X}"
            checksum += byte_val
        
        checksum = (256 - (checksum & 0xFF)) & 0xFF
        record += f"{checksum:02X}"
        
        f.write(record + "\n")
    
    def write_memory_dump(self, dump_filename):
        """Memory dump dosyası oluştur (debug için)"""
        print(f"Creating memory dump: {dump_filename}")
        
        try:
            with open(dump_filename, 'w') as f:
                f.write("MSP430 G2553 Flash Memory Dump\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Generated by: MSP430 Loader v1.0\n")
                f.write(f"Date: {time.ctime()}\n")
                f.write(f"Source ELF: {getattr(self, 'source_elf', 'Unknown')}\n\n")
                
                f.write(f"Flash Memory: 0x{self.flash.FLASH_START:04X} - 0x{self.flash.FLASH_END:04X}\n")
                f.write(f"Entry Point:  0x{self.entry_point:04X}\n")
                f.write(f"Reset Vector: 0x{self.flash.RESET_VECTOR:04X} -> 0x{self.flash.read_word(self.flash.RESET_VECTOR):04X}\n\n")
                
                # Section mapping
                f.write("Section Mapping:\n")
                for section_name, base_addr in self.flash.section_map.items():
                    if section_name in self.sections:
                        size = len(self.sections[section_name]['data'])
                        f.write(f"  {section_name:<12} 0x{base_addr:04X}  {size:4d} bytes\n")
                f.write("\n")
                
                # Memory contents
                f.write("Memory Contents:\n")
                f.write("Address  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII\n")
                f.write("-" * 78 + "\n")
                
                self._write_memory_contents(f)
            
            print(f"Memory dump created: {dump_filename}")
            return True
            
        except Exception as e:
            print(f"Error creating memory dump: {e}")
            return False
    
    def _write_memory_contents(self, f):
        """Memory contents'leri hex dump formatında yaz"""
        addresses = sorted(self.flash.flash_data.keys())
        if not addresses:
            f.write("(Empty flash memory)\n")
            return
        
        start_addr = (addresses[0] // 16) * 16
        end_addr = ((addresses[-1] // 16) + 1) * 16
        
        for addr in range(start_addr, end_addr, 16):
            # Check if this line has any data
            line_has_data = any(addr + i in self.flash.flash_data for i in range(16))
            if not line_has_data:
                continue
            
            line = f"{addr:04X}     "
            ascii_repr = ""
            
            for i in range(16):
                byte_addr = addr + i
                if byte_addr in self.flash.flash_data:
                    byte_val = self.flash.flash_data[byte_addr]
                    line += f"{byte_val:02X} "
                    ascii_repr += chr(byte_val) if 32 <= byte_val <= 126 else '.'
                else:
                    line += "   "
                    ascii_repr += " "
            
            line += f" {ascii_repr}"
            f.write(line + "\n")

def main():
    """Main loader function"""
    if len(sys.argv) != 2:
        print("MSP430 G2553 Loader - Senin Toolchain'in için")
        print("Usage: python msp430_loader.py <firmware.elf>")
        print("Example: python msp430_loader.py program.elf")
        print()
        print("Note: ELF dosyası senin msp430_linker.py'dan gelmelidir")
        return 1
    
    elf_file = sys.argv[1]
    output_prefix = os.path.splitext(elf_file)[0]
    
    # Create loader instance
    loader = MSP430Loader()
    loader.source_elf = elf_file  # Debug için
    
    print("MSP430 G2553 Flash Loader")
    print("=" * 40)
    print(f"Toolchain: Assembler -> Linker -> Loader")
    print(f"Target: MSP430 G2553 Flash Memory")
    print()
    
    # Load ELF executable
    success = loader.load_elf_executable(elf_file)
    
    if success:
        # Create output files
        hex_success = loader.write_intel_hex(f"{output_prefix}.hex")
        dump_success = loader.write_memory_dump(f"{output_prefix}.dump")
        
        if hex_success and dump_success:
            print("\n" + "="*50)
            print("LOADER COMPLETED SUCCESSFULLY!")
            print("="*50)
            print(f"Output files:")
            print(f"  {output_prefix}.hex  - Intel HEX for programming")
            print(f"  {output_prefix}.dump - Memory dump for debugging")
            print(f"\nTo program MSP430 G2553:")
            print(f"  Method 1: mspdebug rf2500 'prog {output_prefix}.hex'")
            print(f"  Method 2: Code Composer Studio -> Load {output_prefix}.hex")
            print(f"  Method 3: MSP-FET with UniFlash -> {output_prefix}.hex")
            print(f"  Method 4: Energia IDE -> Sketch -> Add File -> {output_prefix}.hex")
            
            return 0
        else:
            print("Warning: Some output files could not be created")
            return 1
    else:
        print("Loader failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())