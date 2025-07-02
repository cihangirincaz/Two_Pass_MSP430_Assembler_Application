#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSP430 G2553 Assembler
İki geçişli assembler uygulaması - MSP430 Makro Format Desteği
"""

import sys
import os
import re
import struct
import time

# Karakter kodlaması sorunlarını çözmek için
import io
import codecs

# Makro işlemcisini import et
try:
    from macro import MacroProcessor, MacroExpansion
except ImportError:
    print("HATA: macro.py dosyası bulunamadı!")
    print("macro.py dosyasının main.py ile aynı klasörde olduğundan emin olun.")
    sys.exit(1)

# ELF Object Writer'ı import et
try:
    from elf_object_writer import ELFObjectWriter
    ELF_WRITER_AVAILABLE = True
except ImportError:
    print("UYARI: elf_object_writer.py dosyası bulunamadı!")
    print("Basit ELF formatı kullanılacak.")
    ELF_WRITER_AVAILABLE = False

# Windows için konsol kodlamasını ayarla
if sys.platform == 'win32':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)  # UTF-8 için
    except:
        pass

# Standart çıktı ve hata akışlarını UTF-8 olarak ayarla
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# MSP430 G2553 komut seti (OPTAB)
OPTAB = {
    # Format: 'opcode': (machine_code, instruction_length, operand_count, format_type)
    # format_type: 0=Register only, 1=Single operand, 2=Jump, 3=Two operand
    'MOV': (0x4000, 2, 2, 3),   # Kaynak operandı hedef operanda taşır
    'ADD': (0x5000, 2, 2, 3),   # Kaynak operandı hedef operanda ekler
    'SUB': (0x8000, 2, 2, 3),   # Kaynak operandı hedef operanddan çıkarır
    'CMP': (0x9000, 2, 2, 3),   # Kaynak ve hedef operandları karşılaştırır
    'AND': (0xF000, 2, 2, 3),   # Mantıksal AND işlemi
    'BIS': (0xD000, 2, 2, 3),   # Bit set (OR işlemi)
    'XOR': (0xE000, 2, 2, 3),   # Exclusive OR işlemi
    'BIC': (0xC000, 2, 2, 3),   # Bit clear
    'JMP': (0x3C00, 2, 1, 2),   # Koşulsuz dallanma
    'JEQ': (0x2400, 2, 1, 2),   # Eşitse dallan
    'JNE': (0x2000, 2, 1, 2),   # Eşit değilse dallan
    'JC':  (0x2800, 2, 1, 2),   # Carry flag set ise dallan
    'JNC': (0x2C00, 2, 1, 2),   # Carry flag set değilse dallan
    'JN':  (0x3000, 2, 1, 2),   # Negatif flag set ise dallan
    'JGE': (0x3400, 2, 1, 2),   # Büyük eşitse dallan
    'JL':  (0x3800, 2, 1, 2),   # Küçükse dallan
    'JZ':  (0x2400, 2, 1, 2),   # Sıfırsa dallan (JEQ ile aynı)
    'JNZ': (0x2000, 2, 1, 2),   # Sıfır değilse dallan (JNE ile aynı)
    'CALL': (0x1280, 2, 1, 1),  # Alt program çağrısı
    'RET': (0x4130, 2, 0, 0),   # Alt programdan dönüş
    'PUSH': (0x1200, 2, 1, 1),  # Yığına değer koy
    'POP': (0x4100, 2, 1, 1),   # Yığından değer al
    'SWPB': (0x1080, 2, 1, 1),  # Byte'ları değiştir
    'RRA': (0x1100, 2, 1, 1),   # Sağa aritmetik kaydırma
    'RRC': (0x1000, 2, 1, 1),   # Sağa carry ile kaydırma
    'SXT': (0x1180, 2, 1, 1),   # İşaret genişletme
    'CLR': (0x4300, 2, 1, 1),   # Temizle (0 yap)
    'NOP': (0x4303, 2, 0, 0),   # İşlem yok
    'DEC': (0x8310, 2, 1, 1),   # Azalt (1 çıkar)
    # MSP430 noktalı komutlar
    'mov.w': (0x4000, 2, 2, 3),   # Word taşıma
    'mov.b': (0x4040, 2, 2, 3),   # Byte taşıma
    'add.w': (0x5000, 2, 2, 3),   # Word toplama
    'add.b': (0x5040, 2, 2, 3),   # Byte toplama
    'sub.w': (0x8000, 2, 2, 3),   # Word çıkarma
    'sub.b': (0x8040, 2, 2, 3),   # Byte çıkarma
    'cmp.w': (0x9000, 2, 2, 3),   # Word karşılaştırma
    'cmp.b': (0x9040, 2, 2, 3),   # Byte karşılaştırma
    'and.w': (0xF000, 2, 2, 3),   # Word AND
    'and.b': (0xF040, 2, 2, 3),   # Byte AND
    'bis.w': (0xD000, 2, 2, 3),   # Word bit set
    'bis.b': (0xD040, 2, 2, 3),   # Byte bit set
    'xor.w': (0xE000, 2, 2, 3),   # Word XOR
    'xor.b': (0xE040, 2, 2, 3),   # Byte XOR
    'bic.w': (0xC000, 2, 2, 3),   # Word bit clear
    'bic.b': (0xC040, 2, 2, 3),   # Byte bit clear
}

# MSP430 Direktifleri
DIRECTIVES = {
    'END': 'END', '.end': '.end', 'BYTE': 'BYTE', '.byte': '.byte',
    'WORD': 'WORD', '.word': '.word', '.skip': '.skip', 'EQU': 'EQU',
    '.equ': '.equ', '.org': '.org', '.text': '.text', '.data': '.data',
    '.bss': '.bss', '.global': '.global', '.align': '.align',
    '.long': '.long', '.sect': '.sect', '.usect': '.usect', '.def': '.def',
    '.retain': '.retain', '.retainrefs': '.retainrefs', '.cdecls': '.cdecls',
    '.stack': '.stack', '.reset': '.reset', '.macro': '.macro', '.endm': '.endm',
    '.asg': '.asg', '.eval': '.eval', '.loop': '.loop', '.endloop': '.endloop',
    '.if': '.if', '.else': '.else', '.endif': '.endif', '.mlib': '.mlib',
    '.mlist': '.mlist', '.mnolist': '.mnolist'
}

# MSP430 Registerları
REGISTERS = {
    'PC': 0x0000, 'R0': 0x0000, 'SP': 0x0001, 'R1': 0x0001,
    'SR': 0x0002, 'R2': 0x0002, 'CG': 0x0003, 'R3': 0x0003,
    'R4': 0x0004, 'R5': 0x0005, 'R6': 0x0006, 'R7': 0x0007,
    'R8': 0x0008, 'R9': 0x0009, 'R10': 0x000A, 'R11': 0x000B,
    'R12': 0x000C, 'R13': 0x000D, 'R14': 0x000E, 'R15': 0x000F
}

# MSP430 G2553 özel sembolleri
MSP430_SYMBOLS = {
    'WDTCTL': 0x0120, 'WDTPW': 0x5A00, 'WDTHOLD': 0x0080,
    'P1DIR': 0x0022, 'P1OUT': 0x0021, 'P1IN': 0x0020, 'P1REN': 0x0027,
    'P1SEL': 0x0026, 'P1SEL2': 0x0041, 'P1IE': 0x0025, 'P1IES': 0x0024,
    'P1IFG': 0x0023, 'P2DIR': 0x002A, 'P2OUT': 0x0029, 'P2IN': 0x0028,
    'P2REN': 0x002F, 'P2SEL': 0x002E, 'P2SEL2': 0x0042, 'P2IE': 0x002D,
    'P2IES': 0x002C, 'P2IFG': 0x002B, 'LED': 0x0001, 'LED_RED': 0x0001,
    'LED_GREEN': 0x0040, 'RESET_VECTOR': 0xFFFE, 'NMI_VECTOR': 0xFFFC,
    '__STACK_END': 0x0400
}

class MacroExpansionInfo:
    """Makro genişletme bilgilerini tutan sınıf"""
    def __init__(self, expansion: MacroExpansion, start_address: int):
        self.expansion = expansion
        self.start_address = start_address
        self.end_address = start_address
        self.addresses = []

# Basit ELF Object Writer (fallback)
class SimpleELFObjectWriter:
    """Basit ELF formatında object dosyası writer'ı (fallback)"""
    
    def __init__(self, assembler):
        self.assembler = assembler
        
    def write_elf_object(self, filename):
        """Basit ELF formatında object dosyası yaz"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ELF Object File (Simple Format)\n")
                f.write("=" * 50 + "\n\n")
                
                f.write("FILE HEADER:\n")
                f.write(f"  Magic:     ELF\n")
                f.write(f"  Class:     ELF32\n")
                f.write(f"  Machine:   MSP430\n")
                f.write(f"  Type:      REL (Relocatable file)\n")
                f.write(f"  Created:   {time.ctime()}\n\n")
                
                # Object code
                f.write("OBJECT CODE:\n")
                f.write("  Address  Code\n")
                f.write("  " + "-" * 20 + "\n")
                for addr, code in self.assembler.object_code:
                    f.write(f"  {addr:04X}     {code}\n")
                
                # Symbol table
                f.write("\nSYMBOL TABLE:\n")
                f.write("  Symbol    Value    Type\n")
                f.write("  " + "-" * 30 + "\n")
                for symbol, info in self.assembler.symbol_info.items():
                    if symbol not in ['WDTCTL', 'P1DIR', 'P1OUT', 'WDTPW', 'WDTHOLD']:
                        f.write(f"  {symbol:<10} {info['value']:04X}    {info['type']}\n")
            
            print(f"Simple ELF object file created: {filename}")
            return True
        except Exception as e:
            print(f"Error creating simple ELF object file: {e}")
            return False

class Assembler:
    def __init__(self):
        self.symtab = {}
        self.intermediate = []
        self.object_code = []
        self.listing = []
        self.obj_format = []
        self.locctr = 0
        self.starting_address = 0
        self.program_length = 0
        self.error_flag = False
        self.current_segment = 'text'
        self.global_symbols = set()
        self.equ_symbols = set()
        self.symbol_info = {}
        self.macro_expansions = []
        self.current_expansion = None
        
        # MSP430 özel sembollerini ekle
        self.symtab.update(MSP430_SYMBOLS)
        for symbol, value in MSP430_SYMBOLS.items():
            symbol_type = 'Register' if ('DIR' in symbol or 'OUT' in symbol or 'IN' in symbol) else 'Constant'
            self.symbol_info[symbol] = {
                'value': value, 'type': symbol_type,
                'segment': '.const', 'scope': 'global'
            }
        
        # Makro işlemcisini başlat
        self.macro_processor = MacroProcessor()

    def parse_line(self, line, macro_processed=False, line_number=0):
        """Bir satırı etiket, opcode ve operand olarak ayrıştırır"""
        label = ""
        opcode = ""
        operand = ""
        current_address = self.locctr
        
        line = line.strip()
        if not line or line.startswith(';'):
            return label, opcode, operand, current_address
        
        # Yorumları temizle
        if ';' in line:
            line = line[:line.index(';')].strip()
            if not line:
                return label, opcode, operand, current_address
        
        # Etiket kontrolü
        if ':' in line:
            parts = line.split(':', 1)
            label = parts[0].strip()
            line = parts[1].strip()
        
        if not line:
            return label, "", "", current_address
        
        # Opcode ve operand ayrıştırma
        parts = line.split(None, 1)
        opcode = parts[0].strip()
        if len(parts) > 1:
            operand = parts[1].strip()
            if ';' in operand:
                operand = operand[:operand.index(';')].strip()
        
        # Makro çağrısı kontrolü
        if opcode and self.macro_processor.is_macro_call(opcode):
            try:
                processed_lines, expansion = self.macro_processor.process_line(line, line_number)
                
                if expansion:
                    expansion_info = MacroExpansionInfo(expansion, self.locctr)
                    self.macro_expansions.append(expansion_info)
                    self.current_expansion = expansion_info
                
                if len(processed_lines) > 1:
                    results = []
                    for processed_line in processed_lines:
                        start_addr = self.locctr
                        result = self.parse_line(processed_line, macro_processed=True, line_number=line_number)
                        if self.current_expansion:
                            self.current_expansion.addresses.append(start_addr)
                        results.append(result)
                    
                    if self.current_expansion:
                        self.current_expansion.end_address = self.locctr
                        self.current_expansion = None
                    return results
                elif len(processed_lines) == 1:
                    return self.parse_line(processed_lines[0], macro_processed=True, line_number=line_number)
                else:
                    return "", "", "", self.locctr
            except Exception as e:
                print(f"Makro işleme hatası: {e}")
        
        # Etiket varsa sembol tablosuna ekle
        if label:
            self.symtab[label] = self.locctr
            label_type = 'Function' if label.lower() in ['reset', 'main'] else 'Label'
            scope = 'global' if label.lower() in ['reset', 'main'] else 'local'
            
            self.symbol_info[label] = {
                'value': self.locctr, 'type': label_type,
                'segment': self.current_segment, 'scope': scope
            }
            
            if scope == 'global':
                self.global_symbols.add(label)
        
        # Direktif kontrolü
        if opcode in DIRECTIVES or opcode.startswith('.'):
            if self.macro_processor.is_macro_directive(opcode):
                return label, opcode, operand, current_address
            
            # Segment direktifleri
            if opcode in ['.text', '.data', '.bss']:
                self.current_segment = opcode[1:]
            elif opcode == '.org':
                try:
                    self.locctr = self.evaluate_expression(operand)
                except:
                    print(f"Error: Invalid address in .org directive: {operand}")
            elif opcode in ['EQU', '.equ']:
                if label:
                    try:
                        value = self.evaluate_expression(operand)
                        self.symtab[label] = value
                        self.symbol_info[label] = {
                            'value': value, 'type': 'Constant',
                            'segment': 'absolute', 'scope': 'local'
                        }
                        self.equ_symbols.add(label)
                    except:
                        print(f"Error: Invalid expression in EQU directive: {operand}")
            elif opcode == '.eval':
                # .eval expression, symbol formatını işle
                if operand and ',' in operand:
                    expr_part, symbol_part = operand.split(',', 1)
                    expr_part = expr_part.strip()
                    symbol_part = symbol_part.strip()
                    
                    try:
                        value = self.evaluate_expression(expr_part)
                        self.symtab[symbol_part] = value
                        self.symbol_info[symbol_part] = {
                            'value': value, 'type': 'Variable',
                            'segment': 'data', 'scope': 'local'
                        }
                        # Makro assignments'a da ekle
                        if hasattr(self, 'macro_assignments'):
                            self.macro_assignments[symbol_part] = value
                    except:
                        print(f"Error: Invalid expression in .eval directive: {operand}")
            elif opcode == '.string':
                if operand and operand.startswith('"') and operand.endswith('"'):
                    string = operand[1:-1]
                    self.locctr += len(string) + 1  # +1 for null terminator
            elif opcode in ['BYTE', '.byte']:
                if operand:
                    values = operand.split(',')
                    self.locctr += len(values)
            elif opcode in ['WORD', '.word']:
                if operand:
                    values = operand.split(',')
                    self.locctr += 2 * len(values)
        
        # Komut kontrolü
        elif opcode:
            if opcode in OPTAB or opcode.upper() in OPTAB or opcode.lower() in OPTAB:
                self.locctr += 2
            else:
                print(f"Warning: Unknown opcode: {opcode}")
        
        return label, opcode, operand, current_address

    def pass1(self, input_file):
        """Pass 1: Sembol tablosunu oluşturur"""
        print(f"Starting Pass 1 for {input_file}...")
        
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            try:
                with open(input_file, 'r', encoding='latin-1') as f:
                    lines = f.readlines()
            except Exception as e:
                print(f"Error reading input file: {e}")
                return False
        
        self.locctr = 0xC000
        self.starting_address = self.locctr
        
        # Makro işlenmış satırları topla
        processed_lines = []
        for i, line in enumerate(lines):
            try:
                processed_lines_from_macro, expansion = self.macro_processor.process_line(line.rstrip(), i + 1)
                if expansion:
                    expansion_info = MacroExpansionInfo(expansion, self.locctr)
                    self.macro_expansions.append(expansion_info)
                processed_lines.extend(processed_lines_from_macro)
            except Exception as e:
                print(f"Makro işleme hatası satır {i+1}: {e}")
                processed_lines.append(line.rstrip())
        
        # Makro işlemcisinden .asg atamalarını al
        self.macro_assignments = self.macro_processor.get_assignments()
        
        # İşlenmiş satırları parse et
        for i, line in enumerate(processed_lines):
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            if ';' in line:
                line = line[:line.index(';')].strip()
                if not line:
                    continue
            
            parse_result = self.parse_line(line, macro_processed=True, line_number=i+1)
            
            if isinstance(parse_result, list):
                for result in parse_result:
                    label, opcode, operand, address = result
                    self._process_parsed_line(label, opcode, operand, address)
            else:
                label, opcode, operand, address = parse_result
                self._process_parsed_line(label, opcode, operand, address)
        
        self.program_length = self.locctr - self.starting_address
        
        # RESET ve main etiketlerini ayarla
        if "RESET" not in self.symtab:
            self.symtab["RESET"] = 0xC000
            self.symbol_info["RESET"] = {
                'value': 0xC000, 'type': 'Function',
                'segment': 'text', 'scope': 'global'
            }
        
        if "main" not in self.symtab:
            self.symtab["main"] = 0xC00A
            self.symbol_info["main"] = {
                'value': 0xC00A, 'type': 'Function',
                'segment': 'text', 'scope': 'global'
            }
        
        print("Pass 1 completed.")
        return not self.error_flag

    def _process_parsed_line(self, label, opcode, operand, address):
        """Parse edilmiş satırı işle"""
        self.intermediate.append((label, opcode, operand, address))
        
        if opcode:
            if opcode in OPTAB or opcode.upper() in OPTAB or opcode.lower() in OPTAB:
                instruction_length = 2  # MSP430 komutları 2 byte
                self.locctr += instruction_length
            elif opcode in ['BYTE', '.byte']:
                if operand:
                    values = operand.split(',')
                    self.locctr += len(values)
            elif opcode in ['WORD', '.word']:
                if operand:
                    values = operand.split(',')
                    self.locctr += len(values) * 2

    def pass2(self):
        """Pass 2: Nesne kodunu üretir"""
        print("Starting Pass 2...")
        
        self.obj_format = ["Disassembly of section .text:"]
        
        for i, (label, opcode, operand, address) in enumerate(self.intermediate):
            object_code = ""
            current_address = address
            
            if opcode in ['.cdecls', '.retain', '.retainrefs', '.def', '.global']:
                continue
            
            if self.macro_processor.is_macro_directive(opcode):
                continue
            
            if opcode:
                op_upper = opcode.upper()
                
                if op_upper in OPTAB or opcode in OPTAB:
                    target_opcode = op_upper if op_upper in OPTAB else opcode
                    base_code, _, operand_count, format_type = OPTAB[target_opcode]
                    
                    if operand_count == 0:
                        machine_code = base_code
                        object_code = f"{machine_code:04X}"
                    elif operand_count == 1:
                        if operand:
                            if opcode.upper() == 'JMP' and operand == '$':
                                machine_code = 0x3C3F
                                object_code = f"{machine_code:04X}"
                            else:
                                mode, reg = self.parse_operand(operand, i+1)
                                machine_code = base_code | (mode << 4) | reg
                                object_code = f"{machine_code:04X}"
                        else:
                            machine_code = base_code
                            object_code = f"{machine_code:04X}"
                    elif operand_count == 2:
                        if operand and ',' in operand:
                            src_operand, dst_operand = [op.strip() for op in operand.split(',', 1)]
                            
                            # Özel durumlar
                            if op_upper == 'MOV.W' and src_operand.startswith('#__STACK_END') and dst_operand == 'SP':
                                stack_end_value = self.symtab.get('__STACK_END', 0x0400)
                                machine_code = 0x4031
                                object_code = f"{machine_code:04X}{stack_end_value:04X}"
                            elif op_upper == 'MOV.W' and 'WDTPW' in src_operand and 'WDTHOLD' in src_operand and dst_operand == '&WDTCTL':
                                wdt_value = self.evaluate_expression('WDTPW | WDTHOLD')
                                wdtctl_addr = self.symtab.get('WDTCTL', 0x0120)
                                machine_code = 0x40B0
                                object_code = f"{machine_code:04X}{wdt_value:04X}{wdtctl_addr:04X}"
                            elif op_upper in ['MOV.W', 'MOV'] and src_operand.startswith('#') and dst_operand in REGISTERS:
                                value = self.evaluate_expression(src_operand[1:])
                                dst_reg = REGISTERS[dst_operand]
                                machine_code = 0x4030 | dst_reg
                                object_code = f"{machine_code:04X}{value:04X}"
                            elif op_upper in ['MOV.W', 'MOV'] and src_operand in REGISTERS and dst_operand in REGISTERS:
                                src_reg = REGISTERS[src_operand]
                                dst_reg = REGISTERS[dst_operand]
                                machine_code = 0x4000 | (src_reg << 8) | dst_reg
                                object_code = f"{machine_code:04X}"
                            elif op_upper == 'BIS.B' and src_operand.startswith('#') and dst_operand.startswith('&'):
                                value = self.evaluate_expression(src_operand[1:])
                                dst_addr = self.evaluate_expression(dst_operand[1:])
                                machine_code = 0xD0B0
                                object_code = f"{machine_code:04X}{value:04X}{dst_addr:04X}"
                            elif op_upper == 'ADD.W' and src_operand in REGISTERS and dst_operand in REGISTERS:
                                src_reg = REGISTERS[src_operand]
                                dst_reg = REGISTERS[dst_operand]
                                machine_code = 0x5000 | (src_reg << 8) | dst_reg
                                object_code = f"{machine_code:04X}"
                            else:
                                src_mode, src_reg = self.parse_operand(src_operand, i+1)
                                dst_mode, dst_reg = self.parse_operand(dst_operand, i+1)
                                machine_code = base_code | (src_reg << 8) | (src_mode << 4) | dst_reg | (dst_mode << 7)
                                object_code = f"{machine_code:04X}"
                        else:
                            machine_code = base_code
                            object_code = f"{machine_code:04X}"
                
                # Nesne kodunu kaydet
                if object_code:
                    self.object_code.append((current_address, object_code))
                    
                    # Listeleme satırı oluştur
                    listing_line = f"{current_address:04X}\t{label or ''}\t{opcode or ''}\t{operand or ''}\t{object_code}"
                    self.listing.append(listing_line)
                    
                    # Disassembly satırı oluştur
                    if len(object_code) >= 4:
                        second_byte = object_code[0:2].lower()
                        first_byte = object_code[2:4].lower()
                        bytes_str = f"{first_byte} {second_byte}"
                        
                        if len(object_code) > 4:
                            bytes_str += " " + " ".join([object_code[i:i+2].lower() for i in range(4, len(object_code), 2)])
                    else:
                        bytes_str = object_code.lower()
                    
                    disasm_line = f"{current_address:08x}: {bytes_str.ljust(12)}{opcode}"
                    if operand:
                        disasm_line += f" {operand}"
                    
                    self.obj_format.append(disasm_line)
        
        print("Pass 2 completed.")
        return not self.error_flag

    def evaluate_expression(self, expr):
        """İfadeyi değerlendirir"""
        if not expr:
            return 0
        
        expr = expr.strip()
        
        # Doğrudan sayısal değerler
        if expr.isdigit():
            return int(expr)
        
        # Hex değerler
        if expr.startswith('0x') or expr.startswith('0X'):
            try:
                return int(expr, 16)
            except ValueError:
                pass
        
        # Makro atamalarını kontrol et
        if hasattr(self, 'macro_assignments') and expr in self.macro_assignments:
            assigned_value = self.macro_assignments[expr]
            # Eğer atanan değer string ise, onu da evaluate et
            if isinstance(assigned_value, str):
                # Eğer register ise
                if assigned_value in REGISTERS:
                    return REGISTERS[assigned_value]
                # Diğer durumlarda recursive evaluate
                return self.evaluate_expression(assigned_value)
            return assigned_value
        
        # Sembol tablosunda ara
        if expr in self.symtab:
            return self.symtab[expr]
        
        # Register kontrolü
        if expr in REGISTERS:
            return REGISTERS[expr]
        
        # Çarpma işlemi
        if '*' in expr:
            parts = expr.split('*')
            result = 1
            for part in parts:
                part = part.strip()
                try:
                    result *= self.evaluate_expression(part)
                except:
                    print(f"Warning: Error evaluating expression part: {part}")
                    return 0
            return result
        
        # Bölme işlemi
        if '/' in expr:
            parts = expr.split('/')
            try:
                result = self.evaluate_expression(parts[0].strip())
                for i in range(1, len(parts)):
                    divisor = self.evaluate_expression(parts[i].strip())
                    if divisor != 0:
                        result = int(result / divisor)
                    else:
                        print(f"Warning: Division by zero in expression: {expr}")
                        return 0
                return result
            except:
                print(f"Warning: Error evaluating division expression: {expr}")
                return 0
        
        # Bitwise OR işlemi
        if '|' in expr:
            parts = expr.split('|')
            result = 0
            for part in parts:
                part = part.strip()
                try:
                    result |= self.evaluate_expression(part)
                except:
                    print(f"Warning: Error evaluating expression part: {part}")
                    return 0
            return result
        
        # Toplama işlemi
        if '+' in expr:
            parts = expr.split('+')
            result = 0
            for part in parts:
                part = part.strip()
                try:
                    result += self.evaluate_expression(part)
                except:
                    print(f"Warning: Error evaluating expression part: {part}")
                    return 0
            return result
        
        # Çıkarma işlemi
        if '-' in expr and not expr.startswith('-'):
            parts = expr.split('-', 1)
            try:
                result = self.evaluate_expression(parts[0].strip())
                result -= self.evaluate_expression(parts[1].strip())
                return result
            except:
                print(f"Warning: Error evaluating expression: {expr}")
                return 0
        
        print(f"Warning: Unknown symbol or expression: {expr}, assuming 0")
        return 0

    def parse_operand(self, operand, line_num):
        """Operandı ayrıştırır"""
        if not operand:
            return 0, 0
        
        # Immediate mod: #N
        if operand.startswith('#'):
            return 0, 0
        
        # Register modu: Rn
        if operand in REGISTERS:
            return 0, REGISTERS[operand]
        
        # Dolaylı artırmalı mod: @Rn+
        if operand.startswith('@') and operand.endswith('+'):
            reg_str = operand[1:-1]
            if reg_str in REGISTERS:
                return 3, REGISTERS[reg_str]
            return 0, 0
        
        # Dolaylı mod: @Rn
        if operand.startswith('@'):
            reg_str = operand[1:]
            if reg_str in REGISTERS:
                return 2, REGISTERS[reg_str]
            return 0, 0
        
        # İndeksli mod: X(Rn)
        if '(' in operand and ')' in operand:
            reg_str = operand[operand.find('(')+1:operand.find(')')]
            if reg_str in REGISTERS:
                return 1, REGISTERS[reg_str]
            return 0, 0
        
        # Mutlak mod: &ADDR
        if operand.startswith('&'):
            return 1, 0
        
        return 1, 0

    def write_output(self, output_prefix):
        """Çıktı dosyalarını yazar"""
        try:
            # MSP430 format nesne dosyasını yaz (.o)
            self._write_msp430_object_file(f"{output_prefix}.o")
            
            # Listeleme dosyasını yaz (.lst)
            self._write_macro_listing_file(f"{output_prefix}.lst")
            
            # Sembol tablosu dosyasını yaz (.sym)
            self._write_symbol_table_file(f"{output_prefix}.sym")
            
            # ELF uyumlu obj dosyasını yaz (.obj)
            obj_success = False
            if ELF_WRITER_AVAILABLE:
                try:
                    elf_writer = ELFObjectWriter(self)
                    obj_success = elf_writer.write_elf_object(f"{output_prefix}.obj")
                except Exception as e:
                    print(f"ELF Writer hatası: {e}")
                    obj_success = False
            
            if not obj_success:
                # Fallback: basit ELF writer kullan
                simple_elf_writer = SimpleELFObjectWriter(self)
                simple_elf_writer.write_elf_object(f"{output_prefix}.obj")
            
            # Makro tablosu dosyasını yaz (.mac)
            self._write_macro_table_file(f"{output_prefix}.mac")
            
            print(f"Output files created:")
            print(f"  {output_prefix}.o   - MSP430 format nesne dosyası")
            print(f"  {output_prefix}.lst - Makro genişletmeli listeleme")
            print(f"  {output_prefix}.sym - Sembol tablosu")
            print(f"  {output_prefix}.obj - ELF uyumlu object dosyası")
            print(f"  {output_prefix}.mac - Makro tablosu")
            return True
        
        except Exception as e:
            print(f"Error writing output files: {e}")
            return False

    def _write_msp430_object_file(self, filename):
        """MSP430 formatında .o dosyası yaz"""
        with open(filename, 'w', encoding='utf-8') as f:
            # Makro tanımlarını yaz
            macro_defs = self.macro_processor.get_macro_definitions()
            for name, macro_def in macro_defs.items():
                f.write(f"{macro_def.definition_line}\t{name}\t.macro\t{', '.join(macro_def.parameters)}\n")
                for i, body_line in enumerate(macro_def.body):
                    f.write(f"{macro_def.definition_line + i + 1}\t\t\t{body_line}\n")
                f.write(f"{macro_def.definition_line + len(macro_def.body) + 1}\t\t.endm\n\n")
            
            # Makro genişletmelerini yaz
            for expansion_info in self.macro_expansions:
                expansion = expansion_info.expansion
                f.write(f"{expansion.line_number}\t{expansion_info.start_address:04X}\t{expansion.original_line}\t; Invoke {expansion.macro_name} macro.\n")
                
                for i, expanded_line in enumerate(expansion.expanded_lines):
                    if i < len(expansion_info.addresses):
                        addr = expansion_info.addresses[i]
                        f.write(f"{expansion.line_number}\t{addr:04X}\t\t{expanded_line}\n")
                    else:
                        f.write(f"{expansion.line_number}\t\t\t{expanded_line}\n")
                f.write("\n")

    def _write_macro_listing_file(self, filename):
        """Makro genişletmeli listeleme dosyası yaz"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("MSP430 Assembly Listing with Macro Expansions\n")
            f.write("=" * 60 + "\n")
            f.write("Line\tAddress\tLabel\t\tOpcode\t\tOperand\t\tObject Code\n")
            f.write("-" * 80 + "\n")
            
            for expansion_info in self.macro_expansions:
                expansion = expansion_info.expansion
                f.write(f"{expansion.line_number}\t{expansion_info.start_address:04X}\t\t\t{expansion.original_line}\t; Invoke {expansion.macro_name} macro.\n")
                
                for i, expanded_line in enumerate(expansion.expanded_lines):
                    if i < len(expansion_info.addresses):
                        addr = expansion_info.addresses[i]
                        parts = expanded_line.strip().split()
                        if parts:
                            label = ""
                            opcode = parts[0]
                            operand = " ".join(parts[1:]) if len(parts) > 1 else ""
                            
                            object_code = ""
                            for obj_addr, obj_code in self.object_code:
                                if obj_addr == addr:
                                    object_code = obj_code
                                    break
                            
                            f.write(f"{expansion.line_number}\t{addr:04X}\t\t{label}\t\t{opcode}\t\t{operand}\t\t{object_code}\n")
                    else:
                        f.write(f"{expansion.line_number}\t\t\t\t{expanded_line}\n")
                f.write("\n")
            
            for line in self.listing:
                f.write(f"{line}\n")

    def _write_symbol_table_file(self, filename):
        """Sembol tablosu dosyası yaz"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("MSP430 Symbol Table\n")
            f.write("=" * 60 + "\n")
            f.write("Symbol\t\tValue\t\tType\t\tSegment\t\tScope\n")
            f.write("-" * 70 + "\n")
            
            for symbol, info in sorted(self.symbol_info.items()):
                value = info['value']
                value_str = f"0x{value:04X}" if isinstance(value, int) else str(value)
                f.write(f"{symbol}\t\t{value_str}\t\t{info['type']}\t\t{info['segment']}\t\t{info['scope']}\n")
            
            # Makro bilgilerini de ekle
            macros = self.macro_processor.get_macro_list()
            assignments = self.macro_processor.get_assignments()
            
            if macros or assignments:
                f.write("\n\nMacro Definitions\n")
                f.write("-" * 30 + "\n")
                
                for macro in macros:
                    f.write(f"{macro}\t\t-\t\tMacro\t\t.macro\t\tlocal\n")
                
                for symbol, value in assignments.items():
                    f.write(f"{symbol}\t\t{value}\t\tMacroAssign\t.asg\t\tlocal\n")

    def _write_macro_table_file(self, filename):
        """Makro tablosu dosyası yaz"""
        with open(filename, 'w', encoding='utf-8') as f:
            macro_table = self.macro_processor.generate_macro_table()
            for line in macro_table:
                f.write(f"{line}\n")
            
            f.write("\n\nMacro Expansions\n")
            f.write("=" * 40 + "\n")
            
            for i, expansion_info in enumerate(self.macro_expansions):
                expansion = expansion_info.expansion
                f.write(f"Expansion #{i+1}:\n")
                f.write(f"  Macro: {expansion.macro_name}\n")
                f.write(f"  Arguments: {', '.join(expansion.arguments)}\n")
                f.write(f"  Line: {expansion.line_number}\n")
                f.write(f"  Address: 0x{expansion_info.start_address:04X} - 0x{expansion_info.end_address:04X}\n")
                f.write(f"  Original: {expansion.original_line}\n")
                f.write("  Expanded:\n")
                for expanded_line in expansion.expanded_lines:
                    f.write(f"    {expanded_line}\n")
                f.write("\n")

def main():
    if len(sys.argv) != 2:
        print("Kullanim: python main.py <kaynak_dosyasi>")
        return
    
    input_file = sys.argv[1]
    output_prefix = os.path.splitext(input_file)[0]
    
    assembler = Assembler()
    
    print("MSP430 G2553 Assembler - MSP430 Makro Format Desteği")
    print("=" * 55)
    
    if assembler.pass1(input_file):
        if assembler.pass2():
            assembler.write_output(output_prefix)
            print("\n" + "="*50)
            print("MAKRO RAPORU:")
            print("="*50)
            
            macros = assembler.macro_processor.get_macro_list()
            if macros:
                print(f"Tanımlı makro sayısı: {len(macros)}")
                print(f"Toplam makro genişletmesi: {len(assembler.macro_expansions)}")
                
                for macro_name in macros:
                    macro_def = assembler.macro_processor.get_macro_definitions()[macro_name]
                    print(f"  {macro_name}: {macro_def.call_count} kez çağrıldı")
            else:
                print("Hiç makro tanımı bulunamadı.")
            
            assignments = assembler.macro_processor.get_assignments()
            if assignments:
                print(f"\n.asg atama sayısı: {len(assignments)}")
            
            print("="*50)
            print("Assembler başarıyla tamamlandı!")
        else:
            print("Pass 2 sirasinda hatalar olustu.")
            assembler.write_output(output_prefix)
    else:
        print("Pass 1 sirasinda hatalar olustu.")

if __name__ == "__main__":
    main()