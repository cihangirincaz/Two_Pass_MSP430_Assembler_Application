#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ELF Object Writer for MSP430 G2553 Assembler
MSP430 için ELF formatında object dosyası writer'ı
"""

import time
import struct

class ELFObjectWriter:
    """ELF formatında object dosyası writer'ı"""
    
    def __init__(self, assembler):
        self.assembler = assembler
        
    def write_elf_object(self, filename):
        """ELF formatında object dosyası yaz"""
        try:
            header_info = self._create_header()
            sections = self._create_sections()
            symbols = self._create_symbol_table()
            relocations = self._create_relocation_table()
            
            with open(filename, 'w', encoding='utf-8') as f:
                self._write_elf_format(f, header_info, sections, symbols, relocations)
            
            print(f"ELF object file created: {filename}")
            return True
        except Exception as e:
            print(f"Error creating ELF object file: {e}")
            return False
    
    def _create_header(self):
        """ELF Header bilgileri"""
        return {
            'magic': 'ELF', 
            'class': 'ELF32', 
            'data': 'LSB',
            'version': 1, 
            'osabi': 'SYSV', 
            'machine': 'MSP430',
            'type': 'REL', 
            'entry': 0, 
            'timestamp': int(time.time()),
            'assembler': 'MSP430-Assembler-v1.0'
        }
    
    def _create_sections(self):
        """Section tablosu oluştur - Tam ELF formatı"""
        sections = []
        
        # Section 0: NULL section (her ELF dosyasında olmalı)
        sections.append({
            'name': '', 
            'type': 'NULL', 
            'flags': '',
            'addr': 0x00000000, 
            'offset': 0x000000, 
            'size': 0x000000,
            'data': [], 
            'align': 0,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        # Section 1: .text section (kod bölümü)
        text_data = []
        text_size = 0
        
        for addr, code in self.assembler.object_code:
            if isinstance(code, str) and len(code) >= 4:
                text_data.append((addr, code))
                text_size += len(code) // 2
        
        sections.append({
            'name': '.text', 
            'type': 'PROGBITS', 
            'flags': 'AX',  # Allocate + Execute
            'addr': 0x00000000,  # Relative address 
            'offset': 0x000040, 
            'size': text_size,
            'data': text_data, 
            'align': 2,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        # Section 2: .reset section (MSP430 reset vector)
        sections.append({
            'name': '.reset', 
            'type': 'PROGBITS', 
            'flags': 'AX',
            'addr': 0x0000FFFE,  # MSP430 reset vector address
            'offset': 0x000040 + text_size, 
            'size': 0x000002,  # 2 bytes for reset vector
            'data': [(0xFFFE, "C000")],  # Reset vector points to start of .text
            'align': 2,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        # Section 3: .stack section (stack space)
        stack_size = self._get_stack_size()
        sections.append({
            'name': '.stack', 
            'type': 'NOBITS',  # No data in file
            'flags': 'WA',  # Write + Allocate
            'addr': 0x00000000, 
            'offset': 0x000040 + text_size + 2, 
            'size': stack_size,  # MSP430 tipik stack boyutu
            'data': [], 
            'align': 1,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        # Section 4: .data section (initialized variables only)
        data_items = self._get_data_items()
        data_offset = 0x000040 + text_size + 2
        
        sections.append({
            'name': '.data', 
            'type': 'PROGBITS', 
            'flags': 'WA',  # Write + Allocate
            'addr': 0x00000000, 
            'offset': data_offset, 
            'size': len(data_items) if data_items else 0,
            'data': data_items, 
            'align': 1,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        # Section 5: .bss section (uninitialized data)
        bss_size = self._get_bss_size()
        bss_offset = data_offset + (len(data_items) if data_items else 0)
        
        sections.append({
            'name': '.bss', 
            'type': 'NOBITS', 
            'flags': 'WA',
            'addr': 0x00000000, 
            'offset': bss_offset, 
            'size': bss_size,
            'data': [], 
            'align': 1,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        # Section 6: .strings section (string constants only)
        string_data = self._get_string_data()
        string_offset = bss_offset
        
        sections.append({
            'name': '.strings', 
            'type': 'PROGBITS', 
            'flags': '',  # Read-only strings
            'addr': 0x00000000, 
            'offset': string_offset, 
            'size': len(string_data) if string_data else 0,
            'data': string_data, 
            'align': 1,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        # Section 7: .symtab section (symbol table)
        symbols = self._create_symbol_table()
        symtab_offset = string_offset + (len(string_data) if string_data else 0)
        
        sections.append({
            'name': '.symtab', 
            'type': 'SYMTAB', 
            'flags': '',
            'addr': 0x00000000, 
            'offset': symtab_offset, 
            'size': len(symbols) * 16,  # Each symbol entry is 16 bytes
            'data': symbols, 
            'align': 4,
            'entsize': 16,  # Size of each symbol entry
            'link': 8,  # Links to .strtab
            'info': self._count_local_symbols(symbols)  # Index of first global symbol
        })
        
        # Section 8: .strtab section (string table)
        strtab_size = self._calculate_strtab_size(symbols)
        strtab_offset = symtab_offset + len(symbols) * 16
        
        sections.append({
            'name': '.strtab', 
            'type': 'STRTAB', 
            'flags': '',
            'addr': 0x00000000, 
            'offset': strtab_offset, 
            'size': strtab_size,
            'data': [], 
            'align': 1,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        # Section 9: .shstrtab section (section header string table)
        sections.append({
            'name': '.shstrtab', 
            'type': 'STRTAB', 
            'flags': '',
            'addr': 0x00000000, 
            'offset': strtab_offset + strtab_size, 
            'size': 0x000040,  # Estimated size for section names
            'data': [], 
            'align': 1,
            'entsize': 0,
            'link': 0,
            'info': 0
        })
        
        return sections
    
    def _create_symbol_table(self):
        """Symbol tablosu oluştur"""
        symbols = [
            {
                'name': '', 
                'value': 0, 
                'size': 0, 
                'type': 'NOTYPE', 
                'bind': 'LOCAL', 
                'section': 'UNDEF'
            }
        ]
        
        # MSP430 built-in sembollerini dahil et (önemli olanlar)
        important_symbols = ['WDTCTL', 'P1DIR', 'P1OUT', '__STACK_END']
        for symbol in important_symbols:
            if symbol in self.assembler.symtab:
                symbols.append({
                    'name': symbol, 
                    'value': self.assembler.symtab[symbol], 
                    'size': 2,  # MSP430 word size
                    'type': 'OBJECT', 
                    'bind': 'GLOBAL', 
                    'section': 'ABS'
                })
        
        # User-defined sembollerini ekle
        skip_symbols = {
            'WDTPW', 'WDTHOLD', 'P1REN', 'P1SEL', 'P1SEL2', 'P1IE', 'P1IES', 'P1IFG',
            'P2DIR', 'P2OUT', 'P2IN', 'P2REN', 'P2SEL', 'P2SEL2', 
            'P2IE', 'P2IES', 'P2IFG', 'LED', 'LED_RED', 'LED_GREEN',
            'RESET_VECTOR', 'NMI_VECTOR', 'P1IN'
        }
        
        for symbol, info in self.assembler.symbol_info.items():
            if symbol in important_symbols or symbol in skip_symbols:
                continue
                
            # Symbol tipini belirle
            if info['type'] == 'Function':
                symbol_type = 'FUNC'
                symbol_size = 8  # Ortalama fonksiyon boyutu
            elif info['type'] in ['Variable', 'Label']:
                symbol_type = 'OBJECT'
                symbol_size = 2
            else:
                symbol_type = 'NOTYPE'
                symbol_size = 0
            
            # Bind tipini belirle
            bind = 'GLOBAL' if info['scope'] == 'global' or symbol in self.assembler.global_symbols else 'LOCAL'
            
            # Section'ı belirle
            if info['segment'] == 'text':
                section = '.text'
            elif info['segment'] == 'data':
                section = '.data'
            elif info['segment'] == 'bss':
                section = '.bss'
            elif info['segment'] == 'absolute':
                section = 'ABS'
            else:
                section = '.text'  # default
            
            symbols.append({
                'name': symbol, 
                'value': info['value'], 
                'size': symbol_size,
                'type': symbol_type, 
                'bind': bind, 
                'section': section
            })
        
        return symbols
    
    def _create_relocation_table(self):
        """Relocation tablosu oluştur"""
        relocations = []
        processed_addresses = set()
        
        # Object code'u incele ve relocation'ları bul
        for addr, code in self.assembler.object_code:
            if addr in processed_addresses:
                continue
                
            # Address offset'i hesapla (relative)
            relative_addr = addr - 0xC000 if addr >= 0xC000 else addr
            
            # Uzun komutları kontrol et (6+ hex karakter = external reference)
            if len(code) > 4:
                # Hangi sembollerin bu adreste kullanıldığını bul
                for label, opcode, operand, line_addr in self.assembler.intermediate:
                    if line_addr == addr and operand:
                        # WDTCTL referansı
                        if 'WDTCTL' in operand:
                            relocations.append({
                                'offset': relative_addr + 4,  # Address field offset
                                'symbol': 'WDTCTL',
                                'type': 'R_MSP430_16', 
                                'addend': 0
                            })
                        # P1DIR referansı
                        elif 'P1DIR' in operand:
                            relocations.append({
                                'offset': relative_addr + 4,
                                'symbol': 'P1DIR',
                                'type': 'R_MSP430_16', 
                                'addend': 0
                            })
                        # P1OUT referansı
                        elif 'P1OUT' in operand:
                            relocations.append({
                                'offset': relative_addr + 4,
                                'symbol': 'P1OUT',
                                'type': 'R_MSP430_16', 
                                'addend': 0
                            })
                        # __STACK_END referansı
                        elif '__STACK_END' in operand:
                            relocations.append({
                                'offset': relative_addr + 2,
                                'symbol': '__STACK_END',
                                'type': 'R_MSP430_16', 
                                'addend': 0
                            })
                        break
                
                processed_addresses.add(addr)
        
        return relocations
    
    def _get_data_items(self):
        """Veri öğelerini topla (.data section için - sadece değişkenler)"""
        data_items = []
        
        # Intermediate code'dan BYTE ve WORD direktiflerini al
        for label, opcode, operand, address in self.assembler.intermediate:
            if opcode in ['BYTE', '.byte']:
                if operand:
                    values = operand.split(',')
                    for val in values:
                        val = val.strip()
                        try:
                            data_items.append(self.assembler.evaluate_expression(val) & 0xFF)
                        except:
                            data_items.append(0)
            elif opcode in ['WORD', '.word']:
                if operand:
                    values = operand.split(',')
                    for val in values:
                        val = val.strip()
                        try:
                            word_val = self.assembler.evaluate_expression(val)
                            data_items.append(word_val & 0xFF)
                            data_items.append((word_val >> 8) & 0xFF)
                        except:
                            data_items.extend([0, 0])
        
        # Kodunuzda .byte/.word direktifi yok, bu yüzden boş liste doğru
        return data_items
    
    def _get_stack_size(self):
        """Stack boyutunu hesapla"""
        # Assembly kodu'ndan .sect .stack directive'ini bul
        for label, opcode, operand, address in self.assembler.intermediate:
            if opcode == '.sect' and operand and '.stack' in operand:
                # MSP430 için tipik stack boyutu
                return 0x200  # 512 bytes - MSP430 standard
            elif opcode == '.stack':
                if operand:
                    try:
                        return self.assembler.evaluate_expression(operand)
                    except:
                        pass
        
        # Eğer .sect .stack varsa ama boyut belirtilmemişse, default boyut
        return 0x200  # 512 bytes
    
    def _get_bss_size(self):
        """BSS section boyutunu hesapla"""
        bss_size = 0
        
        # .skip direktiflerini ara
        for label, opcode, operand, address in self.assembler.intermediate:
            if opcode == '.skip':
                if operand:
                    try:
                        bss_size += self.assembler.evaluate_expression(operand)
                    except:
                        pass
        
        # Kodunuzda .skip yok, bu yüzden 0 doğru
        return bss_size
    
    def _get_string_data(self):
        """String verilerini topla"""
        string_data = []
        
        # Makro genişletmelerinden string'leri al
        for expansion_info in self.assembler.macro_expansions:
            expansion = expansion_info.expansion
            for line in expansion.expanded_lines:
                if '.string' in line:
                    import re
                    matches = re.findall(r'"([^"]*)"', line)
                    for match in matches:
                        string_data.extend([ord(c) for c in match])
                        string_data.append(0)  # null terminator
        
        return string_data
    
    def _count_local_symbols(self, symbols):
        """Local symbol sayısını hesapla"""
        count = 0
        for symbol in symbols:
            if symbol['bind'] == 'LOCAL':
                count += 1
            else:
                break  # Global symbols start after local ones
        return count
    
    def _calculate_strtab_size(self, symbols):
        """String table boyutunu hesapla"""
        total_size = 1  # NULL string at beginning
        for symbol in symbols:
            total_size += len(symbol['name']) + 1  # +1 for null terminator
        return total_size
    
    def _write_elf_format(self, f, header, sections, symbols, relocations):
        """ELF formatında dosya yaz"""
        f.write("ELF Object File Format\n")
        f.write("=" * 50 + "\n\n")
        
        # File Header
        f.write("FILE HEADER:\n")
        f.write(f"  Magic:     {header['magic']}\n")
        f.write(f"  Class:     {header['class']}\n")
        f.write(f"  Data:      {header['data']} (Little Endian)\n")
        f.write(f"  Version:   {header['version']}\n")
        f.write(f"  OS/ABI:    {header['osabi']}\n")
        f.write(f"  Machine:   {header['machine']}\n")
        f.write(f"  Type:      {header['type']} (Relocatable file)\n")
        f.write(f"  Entry:     0x{header['entry']:08x}\n")
        f.write(f"  Created:   {time.ctime(header['timestamp'])}\n")
        f.write(f"  Assembler: {header['assembler']}\n\n")
        
        # Section Headers
        f.write("SECTION HEADERS:\n")
        f.write("  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al\n")
        f.write("  " + "-" * 78 + "\n")
        
        for i, section in enumerate(sections):
            flags_str = section.get('flags', '')
            link = section.get('link', 0)
            info = section.get('info', 0)
            entsize = section.get('entsize', 0)
            
            f.write(f"  [{i:2d}] {section['name']:<16} {section['type']:<14} ")
            f.write(f"{section['addr']:08x} {section['offset']:06x} {section['size']:06x} ")
            f.write(f"{entsize:02x} {flags_str:>3} {link:2d} {info:3d} {section['align']:2d}\n")
        
        f.write("\nKey to Flags:\n")
        f.write("  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n")
        f.write("  L (link order), O (extra OS processing required), G (group), T (TLS),\n")
        f.write("  C (compressed), x (unknown), o (OS specific), E (exclude),\n")
        f.write("  p (processor specific)\n\n")
        
        # Symbol Table
        f.write("SYMBOL TABLE:\n")
        f.write("  [Nr]    Value  Size Type    Bind   Vis      Ndx Name\n")
        f.write("  " + "-" * 60 + "\n")
        
        for i, symbol in enumerate(symbols):
            # Section index'i düzelt
            if symbol['section'] == 'ABS':
                ndx = "ABS"
            elif symbol['section'] == 'UNDEF':
                ndx = "UND"
            elif symbol['section'] == '.text':
                ndx = "1"  # .text section index
            elif symbol['section'] == '.data':
                ndx = "2"  # .data section index
            else:
                ndx = str(i)
                
            f.write(f"  [{i:3d}] {symbol['value']:08x} {symbol['size']:4d} ")
            f.write(f"{symbol['type']:<7} {symbol['bind']:<6} DEFAULT {ndx:<3} ")
            f.write(f"{symbol['name']}\n")
        
        # Relocation Table
        if relocations:
            f.write("\nRELOCATION RECORDS FOR [.text]:\n")
            f.write("  Offset   Info     Type              Symbol's Value  Symbol's Name\n")
            f.write("  " + "-" * 70 + "\n")
            for i, rel in enumerate(relocations):
                symbol_value = self.assembler.symtab.get(rel['symbol'], 0)
                f.write(f"  {rel['offset']:08x} {i+1:08x} {rel['type']:<16} ")
                f.write(f"{symbol_value:015x} {rel['symbol']}\n")
        
        # Section Contents
        f.write("\nSECTION CONTENTS:\n")
        for section in sections:
            if section['data'] and section['name'] not in ['.bss', '.stack', '.symtab', '.strtab', '.shstrtab']:
                f.write(f"\nContents of section {section['name']}:\n")
                
                if section['name'] == '.text':
                    # Text section - machine code
                    current_offset = 0
                    for addr, code in section['data']:
                        # MSP430 little endian format
                        bytes_per_line = 16
                        for i in range(0, len(code), bytes_per_line * 2):
                            hex_chunk = code[i:i + bytes_per_line * 2]
                            
                            # Convert to little endian byte format
                            bytes_list = []
                            for j in range(0, len(hex_chunk), 2):
                                if j + 1 < len(hex_chunk):
                                    bytes_list.append(hex_chunk[j:j+2])
                            
                            formatted_hex = ' '.join(bytes_list)
                            f.write(f"  {current_offset:04x} {formatted_hex:<47}\n")
                            current_offset += len(bytes_list)
                
                elif section['name'] == '.reset':
                    # Reset vector
                    for addr, code in section['data']:
                        f.write(f"  fffe {code[2:4]} {code[0:2]}                                    \n")
                
                elif section['name'] == '.data':
                    # Data section - initialized variables only
                    data = section['data']
                    if data:  # Sadece data varsa göster
                        bytes_per_line = 16
                        for i in range(0, len(data), bytes_per_line):
                            line_addr = i
                            line_data = data[i:i + bytes_per_line]
                            hex_bytes = ' '.join(f"{b:02x}" for b in line_data)
                            
                            # ASCII representation
                            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
                            
                            f.write(f"  {line_addr:04x} {hex_bytes:<47} {ascii_repr}\n")
                
                elif section['name'] == '.strings':
                    # String section
                    data = section['data']
                    if data:
                        bytes_per_line = 16
                        for i in range(0, len(data), bytes_per_line):
                            line_addr = i
                            line_data = data[i:i + bytes_per_line]
                            hex_bytes = ' '.join(f"{b:02x}" for b in line_data)
                            
                            # ASCII representation
                            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
                            
                            f.write(f"  {line_addr:04x} {hex_bytes:<47} {ascii_repr}\n")
        
        # Assembly listing
        if hasattr(self.assembler, 'listing') and self.assembler.listing:
            f.write("\nASSEMBLY LISTING:\n")
            f.write("  Address  Label      Opcode     Operand          Object Code\n")
            f.write("  " + "-" * 65 + "\n")
            for line in self.assembler.listing[:10]:  # İlk 10 satır
                f.write(f"  {line}\n")
            if len(self.assembler.listing) > 10:
                f.write(f"  ... ({len(self.assembler.listing) - 10} more lines)\n")
        
        f.write(f"\nEnd of ELF object file.\n")