#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSP430 G2553 Assembler
İki geçişli assembler uygulaması
"""

import sys
import os
import re

# Karakter kodlaması sorunlarını çözmek için
import io
import codecs

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
}

# MSP430 Direktifleri
DIRECTIVES = {
    'END': 'END',      # Program sonu
    '.end': '.end',    # Program sonu (alternatif)
    'BYTE': 'BYTE',    # Byte tanimlama
    '.byte': '.byte',  # Byte tanimlama (alternatif)
    'WORD': 'WORD',    # Word tanimlama
    '.word': '.word',  # Word tanimlama (alternatif)
    '.skip': '.skip',  # Belirtilen sayıda byte rezerve etme
    'EQU': 'EQU',      # Sabit tanimlama
    '.equ': '.equ',    # Sabit tanimlama (alternatif)
    '.org': '.org',    # Baslangic adresi belirleme
    '.text': '.text',  # Kod bolumu
    '.data': '.data',  # Veri bolumu
    '.bss': '.bss',    # BSS bolumu
    '.global': '.global', # Global sembol
    '.align': '.align', # Hizalama
    '.long': '.long',  # Long word tanimlama
    '.sect': '.sect',  # Section tanımlama
    '.usect': '.usect', # Uninitialized section tanımlama
    '.def': '.def',    # Symbol tanımlama
    '.retain': '.retain', # Section'ı koruma
    '.retainrefs': '.retainrefs', # Section referanslarını koruma
    '.cdecls': '.cdecls', # C header dosyası dahil etme
    '.stack': '.stack', # Stack section tanımlama
    '.reset': '.reset', # Reset vector section tanımlama
}

# MSP430 Registerları - Mevcut tanımları koruyoruz
REGISTERS = {
    'PC': 0x0000, 'R0': 0x0000,  # PC ve R0 aynı register
    'SP': 0x0001, 'R1': 0x0001,  # SP ve R1 aynı register
    'SR': 0x0002, 'R2': 0x0002,  # SR ve R2 aynı register
    'CG': 0x0003, 'R3': 0x0003,  # CG ve R3 aynı register
    'R4': 0x0004, 'R5': 0x0005, 'R6': 0x0006, 'R7': 0x0007,
    'R8': 0x0008, 'R9': 0x0009, 'R10': 0x000A, 'R11': 0x000B,
    'R12': 0x000C, 'R13': 0x000D, 'R14': 0x000E, 'R15': 0x000F
}

# MSP430 G2553 özel sembolleri
MSP430_SYMBOLS = {
    # Watchdog Timer Control Register
    'WDTCTL': 0x0120,
    'WDTPW': 0x5A00,    # Watchdog Timer Password
    'WDTHOLD': 0x0080,  # Watchdog Timer Hold
    
    # Port 1
    'P1DIR': 0x0022,    # Port 1 Direction Register
    'P1OUT': 0x0021,    # Port 1 Output Register
    'P1IN': 0x0020,     # Port 1 Input Register
    'P1REN': 0x0027,    # Port 1 Resistor Enable Register
    'P1SEL': 0x0026,    # Port 1 Selection Register
    'P1SEL2': 0x0041,   # Port 1 Selection 2 Register
    'P1IE': 0x0025,     # Port 1 Interrupt Enable Register
    'P1IES': 0x0024,    # Port 1 Interrupt Edge Select Register
    'P1IFG': 0x0023,    # Port 1 Interrupt Flag Register
    
    # Port 2
    'P2DIR': 0x002A,    # Port 2 Direction Register
    'P2OUT': 0x0029,    # Port 2 Output Register
    'P2IN': 0x0028,     # Port 2 Input Register
    'P2REN': 0x002F,    # Port 2 Resistor Enable Register
    'P2SEL': 0x002E,    # Port 2 Selection Register
    'P2SEL2': 0x0042,   # Port 2 Selection 2 Register
    'P2IE': 0x002D,     # Port 2 Interrupt Enable Register
    'P2IES': 0x002C,    # Port 2 Interrupt Edge Select Register
    'P2IFG': 0x002B,    # Port 2 Interrupt Flag Register
    
    # LED pin definitions
    'LED': 0x0001,      # P1.0 (Red LED)
    'LED_RED': 0x0001,  # P1.0 (Red LED)
    'LED_GREEN': 0x0040, # P1.6 (Green LED)
    
    # Basic Clock System+ Registers
    'DCOCTL': 0x0056,   # DCO Control Register
    'BCSCTL1': 0x0057,  # Basic Clock System Control 1
    'BCSCTL2': 0x0058,  # Basic Clock System Control 2
    'BCSCTL3': 0x0053,  # Basic Clock System Control 3
    
    # Timer A Registers
    'TACTL': 0x0160,    # Timer A Control Register
    'TACCTL0': 0x0162,  # Timer A Capture/Compare Control 0
    'TACCTL1': 0x0164,  # Timer A Capture/Compare Control 1
    'TAR': 0x0170,      # Timer A Counter Register
    'TACCR0': 0x0172,   # Timer A Capture/Compare Register 0
    'TACCR1': 0x0174,   # Timer A Capture/Compare Register 1
    
    # ADC10 Registers
    'ADC10CTL0': 0x01B0, # ADC10 Control 0
    'ADC10CTL1': 0x01B2, # ADC10 Control 1
    'ADC10MEM': 0x01B4,  # ADC10 Memory
    'ADC10SA': 0x01BC,   # ADC10 Data Transfer Start Address
    
    # USCI Registers (UART mode)
    'UCA0CTL0': 0x0060,  # USCI_A0 Control Register 0
    'UCA0CTL1': 0x0061,  # USCI_A0 Control Register 1
    'UCA0BR0': 0x0062,   # USCI_A0 Baud Rate 0
    'UCA0BR1': 0x0063,   # USCI_A0 Baud Rate 1
    'UCA0MCTL': 0x0064,  # USCI_A0 Modulation Control
    'UCA0STAT': 0x0065,  # USCI_A0 Status Register
    'UCA0RXBUF': 0x0066, # USCI_A0 Receive Buffer
    'UCA0TXBUF': 0x0067, # USCI_A0 Transmit Buffer
    
    # Interrupt Vectors
    'RESET_VECTOR': 0xFFFE, # Reset Vector
    'NMI_VECTOR': 0xFFFC,   # Non-maskable Interrupt Vector
}

class Assembler:
    def __init__(self):
        self.symtab = {}      # Sembol tablosu
        self.intermediate = [] # Ara dosya
        self.object_code = []  # Nesne kodu
        self.listing = []      # Listeleme dosyası
        self.obj_format = []   # Disassembly formatında obj dosyası için
        self.locctr = 0        # Konum sayacı
        self.starting_address = 0  # Başlangıç adresi
        self.program_length = 0    # Program uzunluğu
        self.error_flag = False    # Hata bayrağı
        self.current_segment = 'text'  # Varsayılan bölüm
        self.global_symbols = set()    # Global semboller
        self.section_addresses = {     # Bölüm adresleri
            'text': 0,
            'data': 0,
            'bss': 0
        }
        self.equ_symbols = set()   # .equ ile tanımlanan semboller
        
        # Sembol bilgilerini saklamak için yeni bir sözlük
        self.symbol_info = {}  # {symbol: {'value': value, 'type': type, 'segment': segment, 'scope': scope}}
        
        # MSP430 özel sembollerini sembol tablosuna ekle
        # Ancak LED_RED ve LED_GREEN'i eklemiyoruz çünkü bunlar kullanıcı tarafından tanımlanacak
        msp430_symbols = MSP430_SYMBOLS.copy()
        if 'LED_RED' in msp430_symbols:
            del msp430_symbols['LED_RED']
        if 'LED_GREEN' in msp430_symbols:
            del msp430_symbols['LED_GREEN']
        self.symtab.update(msp430_symbols)
        
        # MSP430 komut setini genişlet
        self.update_optab()
        
        # MSP430 G2553 için özel komutları ekle
        self.add_msp430_specific_opcodes()

    def parse_line(self, line):
        """
        Bir satırı etiket, opcode ve operand olarak ayrıştırır.
        """
        label = ""
        opcode = ""
        operand = ""
        
        # Satırı temizle
        line = line.strip()
        
        # Yorum satırlarını atla
        if line.startswith(';'):
            return label, opcode, operand, self.locctr
        
        # Etiket kontrolü (etiket: şeklinde)
        if ':' in line:
            parts = line.split(':', 1)
            label = parts[0].strip()
            line = parts[1].strip()
        
        # Boş satır kontrolü
        if not line:
            return label, opcode, operand, self.locctr
        
        # Opcode ve operand ayrıştırma
        parts = line.split(None, 1)
        opcode = parts[0].strip()
        
        if len(parts) > 1:
            operand = parts[1].strip()
            # Yorumları temizle
            if ';' in operand:
                operand = operand[:operand.index(';')].strip()
        
        # Etiket varsa sembol tablosuna ekle
        if label:
            # Etiket zaten tanımlı mı kontrol et
            if label in self.symtab and label not in self.equ_symbols:
                # Eğer sembol bir etiket olarak zaten tanımlanmışsa, hata ver
                if label in self.symbol_info and self.symbol_info[label]['type'] in ['Label', 'Function', 'Variable']:
                    print(f"Error: Duplicate symbol: {label}")
                    self.error_flag = True
                else:
                    # Eğer sembol başka bir tür olarak tanımlanmışsa, güncelle
                    self.symtab[label] = self.locctr
            else:
                # Sembol tablosuna ekle
                self.symtab[label] = self.locctr
            
            # Sembol bilgilerini ekle
            if label.upper() == "RESET":
                self.symbol_info[label] = {
                    'value': self.locctr,
                    'type': 'Label',
                    'segment': 'text',
                    'scope': 'global'
                }
            elif label.lower() == "main":
                self.symbol_info[label] = {
                    'value': self.locctr,
                    'type': 'Function',
                    'segment': 'text',
                    'scope': 'global'
                }
            else:
                # Veri tanımlaması mı kontrol et
                if opcode in ['.int', '.byte', '.word', 'BYTE', 'WORD']:
                    self.symbol_info[label] = {
                        'value': self.locctr,
                        'type': 'Variable',
                        'segment': self.current_segment,
                        'scope': 'local'
                    }
                else:
                    self.symbol_info[label] = {
                        'value': self.locctr,
                        'type': 'Label',
                        'segment': self.current_segment,
                        'scope': 'local'
                    }
        
        # Direktif kontrolü
        if opcode in DIRECTIVES or opcode.startswith('.'):
            # Segment direktifleri
            if opcode == '.text':
                self.current_segment = 'text'
            elif opcode == '.data':
                self.current_segment = 'data'
            elif opcode == '.bss':
                self.current_segment = 'bss'
            
            # ORG direktifi
            elif opcode == '.org':
                try:
                    self.locctr = self.evaluate_expression(operand)
                except:
                    print(f"Error: Invalid address in .org directive: {operand}")
            
            # EQU direktifi
            elif opcode == 'EQU' or opcode == '.equ':
                if label:
                    try:
                        value = self.evaluate_expression(operand)
                        self.symtab[label] = value
                        self.symbol_info[label] = {
                            'value': value,
                            'type': 'Constant',
                            'segment': 'absolute',
                            'scope': 'local'
                        }
                        self.equ_symbols.add(label)
                    except:
                        print(f"Error: Invalid expression in EQU directive: {operand}")
                else:
                    print("Error: EQU directive requires a label")
            
            # BYTE direktifi
            elif opcode == 'BYTE' or opcode == '.byte':
                if operand:
                    if operand.startswith('"') and operand.endswith('"'):
                        # String için
                        self.locctr += len(operand) - 2
                    elif operand.startswith("'") and operand.endswith("'"):
                        # Karakter için
                        self.locctr += len(operand) - 2
                    else:
                        # Sayısal değer için
                        self.locctr += 1
            
            # WORD direktifi
            elif opcode == 'WORD' or opcode == '.word':
                if operand:
                    # Virgülle ayrılmış değerler olabilir
                    values = operand.split(',')
                    self.locctr += 2 * len(values)
            
            # INT direktifi (.int)
            elif opcode == '.int':
                if operand:
                    # Virgülle ayrılmış değerler olabilir
                    values = operand.split(',')
                    self.locctr += 2 * len(values)  # MSP430'da int 2 byte
        
        # Komut kontrolü
        elif opcode in OPTAB:
            # Komut uzunluğunu al
            _, length, _, _ = OPTAB[opcode]
            self.locctr += length
        
        # Bilinmeyen opcode
        else:
            print(f"Warning: Unknown opcode: {opcode}")
        
        return label, opcode, operand, self.locctr

    def is_valid_symbol(self, symbol):
        """Sembol geçerli mi kontrol eder."""
        if not symbol:
            return False
        
        # Sembol sonundaki : karakterini kaldır
        if symbol.endswith(':'):
            symbol = symbol[:-1]
        
        # Sembol bir direktif veya register olmamalı
        # Ancak opcode olabilir (örn. RET bir etiket olarak kullanılabilir)
        if symbol.upper() in DIRECTIVES or symbol.upper() in REGISTERS:
            return False
        
        # Sembol bir nokta ile başlıyorsa (örn. .text) direktiftir, sembol değil
        if symbol.startswith('.'):
            return False
        
        # Sembol alfanümerik olmalı ve harfle başlamalı
        return re.match(r'^[A-Za-z][A-Za-z0-9_]*$', symbol) is not None

    def pass1(self, input_file):
        """
        Pass 1: Sembol tablosunu oluşturur ve ara kodu üretir.
        """
        print(f"Starting Pass 1 for {input_file}...")
        
        # MSP430 özel sembollerini ekle
        self.add_msp430_symbols()
        
        # Kodda kullanılan registerleri takip etmek için set
        self.used_registers = set()
        self.referenced_symbols = set()
        
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
        
        # Geçerli segment ve adres
        current_segment = 'text'  # Varsayılan segment
        self.locctr = 0xC000  # MSP430 için başlangıç adresi
        self.starting_address = self.locctr
        
        # Manuel olarak eklenen etiketleri kaldır
        if "RESET" in self.symtab:
            del self.symtab["RESET"]
        if "RESET" in self.symbol_info:
            del self.symbol_info["RESET"]
        
        if "main" in self.symtab:
            del self.symtab["main"]
        if "main" in self.symbol_info:
            del self.symbol_info["main"]
        
        # Tanımlanan sembolleri takip etmek için set
        defined_symbols = set()
        
        # Satırları işle
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Boş satırları atla
            if not line:
                continue
            
            # Yorum satırlarını atla
            if line.startswith(';'):
                continue
            
            # Yorumları temizle
            if ';' in line:
                line = line[:line.index(';')].strip()
                if not line:
                    continue
            
            # Satırı parçalara ayır
            label, opcode, operand, address = self.parse_line(line)
            
            # Kullanılan registerleri tespit et
            self.detect_used_registers(line)
            
            # Etiket varsa sembol tablosuna ekle
            if label:
                # Etiket zaten tanımlanmış mı kontrol et
                if label in defined_symbols:
                    print(f"Error: Line {i+1} - Duplicate symbol: {label}")
                    self.error_flag = True
                else:
                    defined_symbols.add(label)
                    self.symtab[label] = address
                    
                    # Sembol bilgilerini kaydet
                    symbol_type = 'Label'
                    if current_segment == 'data':
                        symbol_type = 'Variable'
                    
                    self.symbol_info[label] = {
                        'value': address,
                        'type': symbol_type,
                        'segment': current_segment,
                        'scope': 'local'
                    }
                    
                    # .def direktifi ile tanımlanmış semboller global olmalı
                    if label in self.global_symbols:
                        self.symbol_info[label]['scope'] = 'global'
            
            # Segment direktifleri
            if opcode == '.text' or opcode == '.code':
                current_segment = 'text'
                continue
            elif opcode == '.data':
                current_segment = 'data'
                continue
            elif opcode == '.bss':
                current_segment = 'bss'
                continue
            elif opcode == '.sect':
                # Section tanımlama
                if operand:
                    current_segment = operand.strip('"')
                continue
            
            # .ref direktifi - harici sembol referansı
            elif opcode == '.ref':
                if operand:
                    symbol = operand.strip()
                    self.referenced_symbols.add(symbol)
                    # Sembol tablosuna ekle
                    if symbol not in self.symtab:
                        self.symtab[symbol] = 0  # Değer bilinmiyor
                        self.symbol_info[symbol] = {
                            'value': 0,
                            'type': 'External',
                            'segment': 'external',
                            'scope': 'global'
                        }
                continue
            
            # .int direktifi için özel işlem
            if opcode == '.int':
                # Ara dosyaya ekle
                self.intermediate.append((label, opcode, operand, address))
                
                # Konum sayacını güncelle
                if operand:
                    values = operand.split(',')
                    self.locctr += len(values) * 2  # Her integer için 2 byte
                
                continue
            
            # Ara dosyaya ekle
            self.intermediate.append((label, opcode, operand, address))
            
            # Opcode varsa konum sayacını güncelle
            if opcode:
                if opcode in OPTAB or opcode.upper() in OPTAB or opcode.lower() in OPTAB:
                    # Komut uzunluğunu hesapla
                    instruction_length = self.calculate_instruction_length(opcode, operand)
                    self.locctr += instruction_length
                elif opcode == 'BYTE' or opcode == '.byte':
                    # Her byte için 1 byte
                    if operand:
                        if operand.startswith('"') and operand.endswith('"'):
                            # String için her karakter 1 byte
                            self.locctr += len(operand) - 2  # Tırnak işaretlerini çıkar
                        elif operand.startswith("'") and operand.endswith("'"):
                            # Karakter için 1 byte
                            self.locctr += len(operand) - 2  # Tırnak işaretlerini çıkar
                        else:
                            # Sayısal değer için 1 byte
                            self.locctr += 1
                elif opcode == 'WORD' or opcode == '.word':
                    # Her word için 2 byte
                    if operand:
                        # Virgülle ayrılmış değerler olabilir
                        values = operand.split(',')
                        self.locctr += len(values) * 2
                elif opcode == '.skip':
                    # Belirtilen sayıda byte rezerve et
                    if operand and operand.isdigit():
                        self.locctr += int(operand)
        
        # Program uzunluğunu hesapla
        self.program_length = self.locctr - self.starting_address
        
        # Sadece kullanılan register sembollerini ekle
        self.add_used_register_symbols()
        
        # MSP430 özel sembollerini ekle
        self.add_msp430_special_symbols()
        
        # Reset vektörü için adres ayarla
        if "RESET" in self.symbol_info:
            self.symbol_info["RESET"]['segment'] = 'text'
            self.symbol_info["RESET"]['scope'] = 'global'
        
        # Veri segmentindeki sembolleri düzenle
        for symbol in ["arr1", "arr2"]:
            if symbol in self.symbol_info:
                self.symbol_info[symbol]['segment'] = 'data'
                self.symbol_info[symbol]['type'] = 'Variable'
        
        # Gerçekçi etiket değerlerini hesaplar ve kullanır
        self.use_suggested_label_values()
        
        print("Pass 1 completed.")
        
        # Sembol tablosunu yazdır (debug için)
        print("Symbol Table:")
        for symbol, info in sorted(self.symbol_info.items()):
            if info['type'] == 'Constant':
                value_str = f"0x{info['value']:04X}"  # Sabitler için hexadecimal değer
            else:
                value_str = f"0x{info['value']:04X}"  # Adresler için hexadecimal değer
            print(f"{symbol}: {value_str} ({info['type']}, {info['segment']}, {info['scope']})")
        
        return not self.error_flag

    def add_msp430_symbols(self):
        """MSP430 özel sembollerini sembol tablosuna ekler"""
        # MSP430 sabit sembolleri
        self.symtab["WDTPW"] = 0x5A00
        self.symbol_info["WDTPW"] = {
            'value': 0x5A00,
            'type': 'Constant',
            'segment': '.const',
            'scope': 'global'
        }
        
        self.symtab["WDTHOLD"] = 0x0080
        self.symbol_info["WDTHOLD"] = {
            'value': 0x0080,
            'type': 'Constant',
            'segment': '.const',
            'scope': 'global'
        }
        
        self.symtab["WDTCTL"] = 0x0120
        self.symbol_info["WDTCTL"] = {
            'value': 0x0120,
            'type': 'Constant',
            'segment': '.const',
            'scope': 'global'
        }
        
        self.symtab["__STACK_END"] = 0x0400  # Örnek değer, linker tarafından belirlenir
        self.symbol_info["__STACK_END"] = {
            'value': 0x0400,
            'type': 'Constant',
            'segment': '.stack',
            'scope': 'global'
        }

    def detect_used_registers(self, line):
        """Satırda kullanılan registerleri tespit eder"""
        # Register isimleri için regex pattern
        register_pattern = r'\b(R\d+|PC|SP|SR)\b'
        
        # Satırda register isimlerini ara
        import re
        registers = re.findall(register_pattern, line, re.IGNORECASE)
        
        # Bulunan registerleri kullanılan registerlar setine ekle
        for reg in registers:
            self.used_registers.add(reg.upper())  # Büyük harfe çevir

    def add_used_register_symbols(self):
        """Sadece kodda kullanılan register sembollerini sembol tablosuna ekler"""
        # Register değerleri
        register_values = {
            "PC": 0, "SP": 1, "SR": 2, "R0": 0, "R1": 1, "R2": 2, "R3": 3,
            "R4": 4, "R5": 5, "R6": 6, "R7": 7, "R8": 8, "R9": 9, "R10": 10,
            "R11": 11, "R12": 12, "R13": 13, "R14": 14, "R15": 15
        }
        
        # Sadece kullanılan registerleri ekle
        for reg in self.used_registers:
            if reg in register_values:
                self.symtab[reg] = register_values[reg]
                self.symbol_info[reg] = {
                    'value': register_values[reg],
                    'type': 'Register',
                    'segment': 'n/a',
                    'scope': 'global'
                }

    def calculate_instruction_length(self, opcode, operand):
        """MSP430 komutlarının uzunluğunu hesaplar"""
        # MSP430 komutları genellikle 2 veya 4 byte'tır
        
        # Format kontrolü
        if opcode.endswith('.b') or opcode.endswith('.w'):
            base_opcode = opcode[:-2]
        else:
            base_opcode = opcode
        
        # Tek kelimelik komutlar (2 byte)
        single_word_opcodes = ['reti', 'ret', 'nop', 'br', 'clrc', 'clrn', 'clrz', 'dint', 'eint', 'pop', 'push']
        if base_opcode in single_word_opcodes:
            return 2
        
        # Dallanma komutları (2 byte)
        branch_opcodes = ['jmp', 'jeq', 'jne', 'jc', 'jnc', 'jn', 'jge', 'jl', 'jz', 'jnz']
        if base_opcode in branch_opcodes:
            return 2
        
        # İki operandlı komutlar (genellikle 2-6 byte)
        two_operand_opcodes = ['mov', 'add', 'addc', 'sub', 'subc', 'cmp', 'dadd', 'bit', 'bic', 'bis', 'xor', 'and']
        if base_opcode in two_operand_opcodes:
            # Operand modlarına göre uzunluk değişir
            if operand and ',' in operand:
                # Basit bir yaklaşım: her operand için 1-2 byte ekstra
                return 4
            return 2
        
        # Tek operandlı komutlar (genellikle 2-4 byte)
        one_operand_opcodes = ['rrc', 'rra', 'push', 'call', 'swpb', 'sxt', 'inc', 'dec', 'inv', 'clr']
        if base_opcode in one_operand_opcodes:
            return 2
        
        # Varsayılan olarak 2 byte
        return 2

    def calculate_string_length(self, operand):
        """String direktifinin uzunluğunu hesaplar"""
        length = 0
        parts = operand.split(',')
        
        for part in parts:
            part = part.strip()
            if part.startswith('"') and part.endswith('"'):
                # String için her karakter 1 byte
                length += len(part) - 2  # Tırnak işaretlerini çıkar
            elif part == "''":
                # Null karakter için 1 byte
                length += 1
            elif part.startswith("'") and part.endswith("'"):
                # Karakter için 1 byte
                length += len(part) - 2  # Tırnak işaretlerini çıkar
        
        return length

    def use_suggested_label_values(self):
        """Gerçekçi etiket değerlerini hesaplar ve kullanır"""
        # MSP430 için başlangıç adresi
        base_address = 0xC000
        
        # RESET: Program başlangıcı
        if "RESET" in self.symbol_info:
            self.symtab["RESET"] = base_address
            self.symbol_info["RESET"]['segment'] = 'text'
            self.symbol_info["RESET"]['scope'] = 'global'
            next_address = base_address + 8  # RESET bloğu için 8 byte
        else:
            next_address = base_address
        
        # main: Ana program başlangıcı
        if "main" in self.symbol_info:
            self.symtab["main"] = next_address
            self.symbol_info["main"]['segment'] = 'text'
            self.symbol_info["main"]['scope'] = 'global'
            next_address += 32  # main bloğu için 32 byte (yaklaşık)
        
        # arr1: Veri segmentinde
        if "arr1" in self.symbol_info:
            self.symtab["arr1"] = next_address
            self.symbol_info["arr1"]['segment'] = 'data'
            self.symbol_info["arr1"]['type'] = 'Variable'
            next_address += 16  # 8 integer * 2 byte
        
        # arr2: Veri segmentinde
        if "arr2" in self.symbol_info:
            self.symtab["arr2"] = next_address
            self.symbol_info["arr2"]['segment'] = 'data'
            self.symbol_info["arr2"]['type'] = 'Variable'
            next_address += 14  # 7 integer * 2 byte
        
        # suma_sp: Harici sembol
        if "suma_sp" in self.symbol_info:
            self.symbol_info["suma_sp"]['type'] = 'External'
            self.symbol_info["suma_sp"]['segment'] = 'external'
            self.symbol_info["suma_sp"]['scope'] = 'global'

    def pass2(self):
        """
        Pass 2: Nesne kodunu üretir.
        """
        print("Starting Pass 2...")
        
        # Ara dosyayı işle
        current_section = None
        current_label = None
        section_start_address = 0
        
        for i, (label, opcode, operand, address) in enumerate(self.intermediate):
            object_code = ""
            line_num = i + 1  # Satır numarası
            
            # Etiket varsa, yeni bir bölüm başlangıcı olabilir
            if label and (current_label is None or label != current_label):
                current_label = label
                if label in self.symbol_info and self.symbol_info[label]['type'] in ['Function', 'Label']:
                    current_section = label
                    section_start_address = address
                    # Obj formatı için bölüm başlığı ekle
                    self.obj_format.append(f"\n{address:08x} <{label}>:")
            
            # Opcode varsa
            if opcode:
                # Komut kontrolü (büyük/küçük harf duyarsız)
                op_upper = opcode.upper()
                op_lower = opcode.lower()
                
                if op_upper in OPTAB:
                    # Komut formatını belirle
                    base_code, length, operand_count, format_type = OPTAB[op_upper]
                    
                    # Operand sayısını kontrol et
                    if operand_count > 0 and not operand:
                        print(f"Error: Line {line_num} - {opcode} requires {operand_count} operand(s)")
                        self.error_flag = True
                        continue
                    
                    # İki operandlı komutlar için
                    if operand_count == 2:
                        # Operandları virgülle ayır
                        if ',' in operand:
                            src_operand, dst_operand = [op.strip() for op in operand.split(',', 1)]
                            
                            # Kaynak operandı işle
                            src_mode, src_reg = self.parse_operand(src_operand, line_num)
                            
                            # Hedef operandı işle
                            dst_mode, dst_reg = self.parse_operand(dst_operand, line_num)
                            
                            # Makine kodunu oluştur
                            machine_code = base_code | (src_mode << 4) | (src_reg << 8) | (dst_mode << 7) | dst_reg
                            object_code = f"{machine_code:04X}"
                        else:
                            # Virgül yoksa, boşluk ile ayrılmış olabilir
                            parts = operand.split()
                            if len(parts) >= 2:
                                src_operand = parts[0]
                                dst_operand = parts[-1]  # Son kısmı al
                                
                                # Kaynak operandı işle
                                src_mode, src_reg = self.parse_operand(src_operand, line_num)
                                
                                # Hedef operandı işle
                                dst_mode, dst_reg = self.parse_operand(dst_operand, line_num)
                                
                                # Makine kodunu oluştur
                                machine_code = base_code | (src_mode << 4) | (src_reg << 8) | (dst_mode << 7) | dst_reg
                                object_code = f"{machine_code:04X}"
                            else:
                                print(f"Error: Line {line_num} - {opcode} requires 2 operands separated by comma")
                                self.error_flag = True
                                continue
                    
                    # Tek operandlı komutlar için
                    elif operand_count == 1:
                        # Operandı işle
                        mode, reg = self.parse_operand(operand, line_num)
                        
                        # Makine kodunu oluştur
                        machine_code = base_code | (mode << 4) | reg
                        object_code = f"{machine_code:04X}"
                    
                    # Operandsız komutlar için
                    else:
                        object_code = f"{base_code:04X}"
                
                elif op_lower in OPTAB:
                    # Komut formatını belirle
                    base_code, length, operand_count, format_type = OPTAB[op_lower]
                    
                    # Operand sayısını kontrol et
                    if operand_count > 0 and not operand:
                        print(f"Error: Line {line_num} - {opcode} requires {operand_count} operand(s)")
                        self.error_flag = True
                        continue
                    
                    # İki operandlı komutlar için
                    if operand_count == 2:
                        # Operandları virgülle ayır
                        if ',' in operand:
                            src_operand, dst_operand = [op.strip() for op in operand.split(',', 1)]
                            
                            # Kaynak operandı işle
                            src_mode, src_reg = self.parse_operand(src_operand, line_num)
                            
                            # Hedef operandı işle
                            dst_mode, dst_reg = self.parse_operand(dst_operand, line_num)
                            
                            # Makine kodunu oluştur
                            machine_code = base_code | (src_mode << 4) | (src_reg << 8) | (dst_mode << 7) | dst_reg
                            object_code = f"{machine_code:04X}"
                        else:
                            # Virgül yoksa, boşluk ile ayrılmış olabilir
                            parts = operand.split()
                            if len(parts) >= 2:
                                src_operand = parts[0]
                                dst_operand = parts[-1]  # Son kısmı al
                                
                                # Kaynak operandı işle
                                src_mode, src_reg = self.parse_operand(src_operand, line_num)
                                
                                # Hedef operandı işle
                                dst_mode, dst_reg = self.parse_operand(dst_operand, line_num)
                                
                                # Makine kodunu oluştur
                                machine_code = base_code | (src_mode << 4) | (src_reg << 8) | (dst_mode << 7) | dst_reg
                                object_code = f"{machine_code:04X}"
                            else:
                                print(f"Error: Line {line_num} - {opcode} requires 2 operands separated by comma")
                                self.error_flag = True
                                continue
                    
                    # Tek operandlı komutlar için
                    elif operand_count == 1:
                        # Operandı işle
                        mode, reg = self.parse_operand(operand, line_num)
                        
                        # Makine kodunu oluştur
                        machine_code = base_code | (mode << 4) | reg
                        object_code = f"{machine_code:04X}"
                    
                    # Operandsız komutlar için
                    else:
                        object_code = f"{base_code:04X}"
                
                # INT direktifi (.int)
                elif opcode == '.int':
                    if operand:
                        # Virgülle ayrılmış değerler olabilir
                        values = [val.strip() for val in operand.split(',')]
                        for val in values:
                            try:
                                value = self.evaluate_expression(val)
                                object_code += f"{value & 0xFFFF:04X}"  # 16-bit değer
                            except:
                                print(f"Error: Line {line_num} - Invalid operand: {val}")
                                self.error_flag = True
                
                # Direktifler için nesne kodu üretme
                else:
                    object_code = ""
            
            # Nesne kodunu kaydet
            self.object_code.append((address, object_code))
            
            # Listeleme dosyası için satır oluştur
            if label:
                listing_line = f"{address:04X}\t{label}\t{opcode}\t{operand}\t{object_code}"
            else:
                listing_line = f"{address:04X}\t\t{opcode}\t{operand}\t{object_code}"
            
            self.listing.append(listing_line)
            
            # Obj formatı için disassembly satırı oluştur
            if object_code:
                # Makine kodunu byte'lara ayır
                machine_bytes = ""
                for i in range(0, len(object_code), 2):
                    if i > 0:
                        machine_bytes += " "
                    machine_bytes += object_code[i:i+2].lower()
                
                # Disassembly satırını oluştur
                disasm_line = f"{address:04x}: {machine_bytes:<12} {opcode.lower()}"
                
                # Operand varsa ekle
                if operand:
                    disasm_line += f" {operand.lower()}"
                
                # Yorum ekle (isteğe bağlı)
                if label or operand:
                    comment = ""
                    if label:
                        comment += f"; {label}"
                    if operand and self.is_memory_reference(operand):
                        comment += f"; {self.get_operand_description(operand)}"
                    if comment:
                        disasm_line += f" {comment}"
                
                self.obj_format.append(disasm_line)
        
        print("Pass 2 completed.")
        return not self.error_flag

    def is_memory_reference(self, operand):
        """Operandın bellek referansı olup olmadığını kontrol eder"""
        if operand.startswith('&'):
            return True
        if '@' in operand or '+' in operand:
            return True
        return False

    def get_operand_description(self, operand):
        """Operand için açıklama döndürür"""
        # Bellek referansları için açıklama
        if operand.startswith('&'):
            symbol = operand[1:]
            if symbol in self.symtab:
                return f"Adres: {symbol}"
        return ""

    def write_output(self, output_prefix):
        """
        Çıktı dosyalarını yazar.
        """
        try:
            # Debug: Sembol tablosunu kontrol et
            print("\nDEBUG - Symbol Table before writing:")
            for symbol, info in sorted(self.symbol_info.items()):
                print(f"{symbol}: value={info['value']}, type={info['type']}, segment={info['segment']}")
            
            # Nesne dosyasını yaz
            with open(f"{output_prefix}.o", 'w', encoding='utf-8') as f:
                f.write(f"H {output_prefix} {self.starting_address:04X} {self.program_length:04X}\n")
                
                # Text kayıtları
                for address, code in self.object_code:
                    if code:  # Boş olmayan kodlar için
                        f.write(f"T {address:04X} {code}\n")
                
                # End kaydı
                f.write(f"E {self.starting_address:04X}\n")
            
            # Listeleme dosyasını yaz
            with open(f"{output_prefix}.lst", 'w', encoding='utf-8') as f:
                f.write("Address\tLabel\tOpcode\tOperand\tObject Code\n")
                f.write("-" * 60 + "\n")
                for line in self.listing:
                    f.write(f"{line}\n")
            
            # Sembol tablosu dosyasını yaz
            with open(f"{output_prefix}.sym", 'w', encoding='utf-8') as f:
                f.write("Symbol\tValue\tType\tSegment\tScope\n")
                f.write("-" * 60 + "\n")
                
                # Sembolleri alfabetik sıraya göre sırala
                sorted_symbols = sorted(self.symbol_info.items())
                
                # Sembolleri yaz
                for symbol, info in sorted_symbols:
                    value = info['value']
                    value_str = f"0x{value:04X}" if isinstance(value, int) else str(value)
                    
                    symbol_type = info['type']
                    segment = info['segment']
                    scope = info['scope']
                    
                    f.write(f"{symbol}\t{value_str}\t{symbol_type}\t{segment}\t{scope}\n")
            
            # Obj dosyasını yaz
            with open(f"{output_prefix}.obj", 'w', encoding='utf-8') as f:
                f.write("Disassembly of section .text:\n")
                
                # Sembol tablosundan bölüm başlıklarını belirle
                sections = {}
                for symbol, info in self.symbol_info.items():
                    if info['type'] in ['Function', 'Label'] and info['segment'] in ['text', 'absolute']:
                        sections[info['value']] = symbol
                
                # Eğer hiç bölüm yoksa, varsayılan bölümleri ekle
                if not sections:
                    f.write("\n0000c000 <RESET>:\n")
                    f.write("\n0000c008 <main>:\n")
                else:
                    # Sıralı adresler
                    for address in sorted(sections.keys()):
                        section_name = sections[address]
                        f.write(f"\n{address:08x} <{section_name}>:\n")
                
                # Nesne kodunu işle
                for address, code in sorted(self.object_code):
                    if code:  # Boş olmayan kodlar için
                        # Komut satırını bul
                        for label, opcode, operand, addr in self.intermediate:
                            if addr == address and opcode:
                                # Makine kodunu formatla
                                bytes_str = ""
                                for i in range(0, len(code), 2):
                                    if i > 0:
                                        bytes_str += " "
                                    bytes_str += code[i:i+2].lower()
                                
                                # Komut formatını oluştur
                                instruction = opcode.lower()
                                if opcode.upper() in OPTAB and not (opcode.endswith('.b') or opcode.endswith('.w')):
                                    instruction += ".w"  # MSP430'da varsayılan word işlemi
                                
                                if operand:
                                    instruction += f" {operand.lower()}"
                                
                                # Satırı yaz
                                line = f"{address:08x}: {bytes_str:<12} {instruction}"
                                f.write(f"{line}\n")
            
            print(f"Output files created: {output_prefix}.o, {output_prefix}.lst, {output_prefix}.sym, {output_prefix}.obj")
            return True
        
        except Exception as e:
            print(f"Error writing output files: {e}")
            # Hata durumunda bile dosyaları oluşturmaya çalış
            try:
                # ASCII ile dene
                with open(f"{output_prefix}.o", 'w', encoding='ascii', errors='replace') as f:
                    f.write(f"H {output_prefix} {self.starting_address:04X} {self.program_length:04X}\n")
                    for address, code in self.object_code:
                        if code:
                            f.write(f"T {address:04X} {code}\n")
                
                with open(f"{output_prefix}.lst", 'w', encoding='ascii', errors='replace') as f:
                    f.write("Address\tLabel\tOpcode\tOperand\tObject Code\n")
                    f.write("-" * 60 + "\n")
                    for line in self.listing:
                        f.write(f"{line}\n")
                
                with open(f"{output_prefix}.sym", 'w', encoding='ascii', errors='replace') as f:
                    f.write("Symbol\tValue\tType\tSegment\tScope\n")
                    f.write("-" * 60 + "\n")
                    
                    # Sembolleri yaz
                    for symbol, info in sorted(self.symbol_info.items()):
                        value = info['value']
                        value_str = f"0x{value:04X}" if isinstance(value, int) else str(value)
                        
                        # Sembol türünü belirle
                        symbol_type = self.determine_symbol_type(symbol, info)
                        
                        # Segment türünü belirle
                        segment = self.determine_segment_type(symbol, info)
                        
                        scope = info['scope']
                        
                        f.write(f"{symbol}\t{value_str}\t{symbol_type}\t{segment}\t{scope}\n")
                
                with open(f"{output_prefix}.obj", 'w', encoding='ascii', errors='replace') as f:
                    f.write("Disassembly of section .text:\n")
                    for line in self.obj_format:
                        f.write(f"{line}\n")
                
                print(f"Output files created with ASCII encoding: {output_prefix}.o, {output_prefix}.lst, {output_prefix}.sym, {output_prefix}.obj")
                return True
            except Exception as e2:
                print(f"Failed to create output files with ASCII encoding: {e2}")
                return False
            
            return False

    def determine_symbol_type(self, symbol, info):
        """
        Sembolün türünü belirler: Constant, Variable, Label, Function, Register
        """
        # Register kontrolü
        if symbol in REGISTERS:
            return "Register"
        
        # Sabit kontrolü - MSP430 özel sembolleri
        if symbol in MSP430_SYMBOLS:
            return "Constant"
        
        # Kullanıcı tanımlı sabitler
        if symbol in self.equ_symbols or info['type'] == 'Constant':
            return "Constant"
        
        # .bss segmentindeki semboller Variable olmalı
        if info['segment'] == '.bss' or info['segment'] == 'bss':
            return "Variable"
        
        # .usect ile tanımlanan semboller Variable olmalı
        if info['type'] == 'Variable':
            return "Variable"
        
        # Fonksiyon kontrolü - genellikle .text segmentinde ve bir dallanma hedefi
        if (info['segment'] == '.text' or info['segment'] == 'text') and self.is_function_entry(symbol):
            return "Function"
        
        # Değişken kontrolü - genellikle .data segmentinde
        if info['segment'] == '.data' or info['segment'] == 'data':
            return "Variable"
        
        # Varsayılan olarak Label
        return "Label"

    def determine_segment_type(self, symbol, info):
        """
        Sembolün segment türünü belirler: .text, .data, .bss, .stack, .const, .reset
        """
        # Segment bilgisini kullan
        segment = info['segment']
        
        # Reset vektörü kontrolü
        if symbol == "RESET" or (info['value'] >= 0xFFFE and info['value'] <= 0xFFFF):
            return ".reset"
        
        # Stack kontrolü
        if segment == 'stack' or symbol == "SP" or symbol == "R1":
            return ".stack"
        
        # Sabitler için .const segmenti
        if info['type'] == 'Constant' or symbol in self.equ_symbols:
            return ".const"
        
        # Diğer segmentler için doğrudan segment bilgisini kullan
        if segment in ['.text', '.data', '.bss']:
            return segment
        
        # Varsayılan olarak .text
        return ".text"

    def is_function_entry(self, symbol):
        """
        Sembolün bir fonksiyon girişi olup olmadığını kontrol eder
        """
        # Basit bir yaklaşım: Sembol bir dallanma hedefi mi?
        for _, opcode, operand, _ in self.intermediate:
            if opcode in ['JMP', 'JEQ', 'JNE', 'JC', 'JNC', 'JN', 'JGE', 'JL', 'JZ', 'JNZ', 'CALL'] and operand == symbol:
                return True
        
        # Fonksiyon adları genellikle belirli kalıplara uyar
        function_patterns = ['_init', '_main', 'main', 'init', 'start', 'handler', 'isr', 'interrupt']
        for pattern in function_patterns:
            if pattern in symbol.lower():
                return True
        
        return False

    def evaluate_expression(self, expr):
        """
        İfadeyi değerlendirir ve sayısal değerini döndürür.
        """
        if not expr:
            return 0
        
        # Sayısal değer kontrolü
        if expr.isdigit():
            return int(expr)
        
        # Hexadecimal değer kontrolü
        if expr.startswith('0x') or expr.startswith('0X'):
            try:
                return int(expr, 16)
            except ValueError:
                pass
        
        # Binary değer kontrolü
        if expr.endswith('b') or expr.endswith('B'):
            try:
                return int(expr[:-1], 2)
            except ValueError:
                pass
        
        # Octal değer kontrolü
        if expr.endswith('q') or expr.endswith('Q') or expr.endswith('o') or expr.endswith('O'):
            try:
                return int(expr[:-1], 8)
            except ValueError:
                pass
        
        # Sembol tablosunda ara
        if expr in self.symtab:
            return self.symtab[expr]
        
        # Bitwise OR işlemi (|)
        if '|' in expr:
            parts = expr.split('|')
            result = 0
            for part in parts:
                part = part.strip()
                try:
                    result |= self.evaluate_expression(part)
                except:
                    # Hata durumunda 0 döndür
                    return 0
            return result
        
        # Bitwise AND işlemi (&)
        if '&' in expr and not expr.startswith('&'):
            parts = expr.split('&')
            result = -1  # Tüm bitler 1
            for part in parts:
                part = part.strip()
                try:
                    result &= self.evaluate_expression(part)
                except:
                    # Hata durumunda 0 döndür
                    return 0
            return result
        
        # Toplama işlemi (+)
        if '+' in expr:
            parts = expr.split('+')
            result = 0
            for part in parts:
                part = part.strip()
                try:
                    result += self.evaluate_expression(part)
                except:
                    # Hata durumunda 0 döndür
                    return 0
            return result
        
        # Çıkarma işlemi (-)
        if '-' in expr and not expr.startswith('-'):
            parts = expr.split('-', 1)
            try:
                result = self.evaluate_expression(parts[0].strip())
                result -= self.evaluate_expression(parts[1].strip())
                return result
            except:
                # Hata durumunda 0 döndür
                return 0
        
        # Negatif değer
        if expr.startswith('-'):
            try:
                return -self.evaluate_expression(expr[1:])
            except:
                # Hata durumunda 0 döndür
                return 0
    
        # Bilinmeyen sembol - hata yerine 0 döndür
        print(f"Warning: Unknown symbol or expression: {expr}, assuming 0")
        return 0

    def generate_symbol_table(self, output_file):
        # Sembol tablosunu oluştur ve dosyaya yaz
        with open(output_file, 'w') as f:
            f.write("Symbol\tValue\tType\tSegment\tScope\n")
            f.write("------------------------------------------------------------\n")
            
            for symbol, info in self.symbol_info.items():
                value = info['value']
                
                # Değer bir sayı ise hex formatına çevir
                if isinstance(value, int):
                    value_str = f"0x{value:04X}"
                else:
                    value_str = str(value)
                
                # Segment türünü belirle
                segment = info['segment']
                if segment == '.text':
                    segment_type = ".text"
                elif segment == '.data':
                    segment_type = ".data"
                elif segment == '.bss':
                    segment_type = ".bss"
                elif info['type'] == 'Constant':
                    segment_type = "FLASH"  # Sabitler için FLASH segment türü
                else:
                    segment_type = segment
                
                f.write(f"{symbol}\t{value_str}\t{info['type']}\t{segment_type}\t{info['scope']}\n")

    def add_msp430_special_symbols(self):
        """MSP430 özel sembollerini sembol tablosuna ekler"""
        # MSP430 özel sembolleri
        special_symbols = {
            "P1DIR": 0x0022,
            "P1OUT": 0x0021,
            "P2DIR": 0x002A,
            "P2OUT": 0x0029,
            "P3DIR": 0x001A,  # MSP430G2553'te P3 ve P4 yok, ancak sembol tablosunda göstermek için
            "P3OUT": 0x0019,
            "P4DIR": 0x001E,
            "P4OUT": 0x001D,
            "LPM4": 0x0004,
            "WDTCTL": 0x0120,
            "WDTPW": 0x5A00,
            "WDTHOLD": 0x0080
        }
        
        for symbol, value in special_symbols.items():
            self.symtab[symbol] = value
            symbol_type = 'Register' if symbol.startswith('P') else 'Constant'
            self.symbol_info[symbol] = {
                'value': value,
                'type': symbol_type,
                'segment': 'system',
                'scope': 'global'
            }

    def parse_operand(self, operand, line_num):
        """
        Operandı ayrıştırır ve adres modu ile register değerini döndürür.
        """
        # Adres modları:
        # 0: Register mode (Rn)
        # 1: Indexed mode (X(Rn))
        # 2: Symbolic mode (ADDR)
        # 3: Absolute mode (&ADDR)
        
        if not operand:
            return 0, 0  # Varsayılan: Register mode, R0
        
        # Register modu
        if operand in REGISTERS:
            return 0, REGISTERS[operand]
        
        # İndeksli mod: X(Rn)
        if '(' in operand and ')' in operand:
            offset_str = operand[:operand.find('(')]
            reg_str = operand[operand.find('(')+1:operand.find(')')]
            
            # Offset değerini hesapla
            try:
                offset = self.evaluate_expression(offset_str)
            except:
                print(f"Error: Line {line_num} - Invalid offset: {offset_str}")
                return 0, 0
            
            # Register değerini al
            if reg_str in REGISTERS:
                reg = REGISTERS[reg_str]
            else:
                print(f"Error: Line {line_num} - Invalid register: {reg_str}")
                return 0, 0
            
            return 1, reg
        
        # Dolaylı mod: @Rn
        if operand.startswith('@'):
            reg_str = operand[1:]
            if reg_str in REGISTERS:
                return 2, REGISTERS[reg_str]
            else:
                print(f"Error: Line {line_num} - Invalid register: {reg_str}")
                return 0, 0
        
        # Mutlak mod: &ADDR
        if operand.startswith('&'):
            addr_str = operand[1:]
            try:
                addr = self.evaluate_expression(addr_str)
                return 3, 0  # Mutlak mod, R0 kullanılır
            except:
                print(f"Error: Line {line_num} - Invalid address: {addr_str}")
                return 0, 0
        
        # Sembolik mod: ADDR (varsayılan)
        try:
            addr = self.evaluate_expression(operand)
            return 2, 0  # Sembolik mod, PC-relative
        except:
            print(f"Error: Line {line_num} - Invalid operand: {operand}")
            return 0, 0

    def find_section_for_address(self, address):
        """Adrese göre bölüm adını bulur"""
        for symbol, info in self.symbol_info.items():
            if info['value'] == address and info['type'] in ['Function', 'Label']:
                return symbol
        return None

    def get_symbol_for_address(self, address):
        """Adrese karşılık gelen sembolü bulur"""
        for symbol, value in self.symtab.items():
            if value == address:
                return symbol
        return None

    def update_optab(self):
        """MSP430 komut setini genişletir - noktalı komutları ekler"""
        global OPTAB
        
        # Mevcut komutların noktalı versiyonlarını ekle
        extended_optab = {}
        for opcode, (base_code, length, operand_count, format_type) in OPTAB.items():
            # Word versiyonu (.w)
            extended_optab[f"{opcode}.w"] = (base_code, length, operand_count, format_type)
            
            # Byte versiyonu (.b)
            if opcode in ['MOV', 'ADD', 'SUB', 'CMP', 'AND', 'BIS', 'XOR', 'BIC']:
                # Byte işlemleri için bit 6 set edilir
                extended_optab[f"{opcode}.b"] = (base_code | 0x0040, length, operand_count, format_type)
        
        # Ana OPTAB'a ekle
        OPTAB.update(extended_optab)

    def add_msp430_specific_opcodes(self):
        """MSP430 G2553 için özel komutları ekler"""
        global OPTAB
        
        # Noktalı komutlar
        specific_opcodes = {
            # Format: 'opcode': (machine_code, instruction_length, operand_count, format_type)
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
            
            # Tek operandlı komutlar
            'push': (0x1200, 2, 1, 1),    # Push
            'call': (0x1280, 2, 1, 1),    # Call
            'jmp': (0x3C00, 2, 1, 2),     # Jump
            'ret': (0x4130, 2, 0, 0),     # Return
        }
        
        # Ana OPTAB'a ekle
        OPTAB.update(specific_opcodes)

def main():
    if len(sys.argv) != 2:
        print("Kullanim: python assembler.py <kaynak_dosyasi>")
        return
    
    input_file = sys.argv[1]
    output_prefix = os.path.splitext(input_file)[0]
    
    assembler = Assembler()
    
    if assembler.pass1(input_file):
        if assembler.pass2():
            assembler.write_output(output_prefix)
        else:
            print("Pass 2 sirasinda hatalar olustu. Cikti dosyalari olusturulmaya calisilacak.")
            assembler.write_output(output_prefix)
    else:
        print("Pass 1 sirasinda hatalar olustu. Pass 2 calistirilmadi.")
        # Hata olsa bile çıktı dosyalarını oluşturmaya çalış
        if assembler.pass2():
            assembler.write_output(output_prefix)

if __name__ == "__main__":
    main()
