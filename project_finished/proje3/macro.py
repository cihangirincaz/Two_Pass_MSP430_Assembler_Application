#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSP430 Assembler Makro Sistemi - Tam Düzeltilmiş Versiyon
MSP430 standart makro formatını destekler
"""

import re
import os
from typing import Dict, List, Any, Optional, Union, Tuple

class MacroExpansion:
    """Makro genişletme bilgisi"""
    def __init__(self, macro_name: str, arguments: List[str], expanded_lines: List[str], 
                 original_line: str, line_number: int):
        self.macro_name = macro_name
        self.arguments = arguments
        self.expanded_lines = expanded_lines
        self.original_line = original_line
        self.line_number = line_number
        self.expansion_id = id(self)

class MacroDefinition:
    """Makro tanımı sınıfı"""
    def __init__(self, name: str, parameters: List[str], body: List[str], 
                 definition_line: int = 0, source_file: str = ""):
        self.name = name
        self.parameters = parameters  # Parametre isimleri
        self.body = body             # Makro gövdesi (satır listesi)
        self.local_label_counter = 0  # Yerel etiket sayacı
        self.definition_line = definition_line
        self.source_file = source_file
        self.call_count = 0          # Çağrılma sayısı
    
    def expand(self, arguments: List[str], expansion_id: int = 0, call_line: int = 0) -> MacroExpansion:
        """Makroyu argümanlarla genişlet ve MacroExpansion döndür - TAM DÜZELTİLMİŞ"""
        if len(arguments) != len(self.parameters):
            raise ValueError(f"Makro {self.name}: {len(self.parameters)} parametre bekleniyor, {len(arguments)} verildi")
        
        self.call_count += 1
        print(f"DEBUG: Makro {self.name} genişletiliyor, call_count: {self.call_count}")
        
        # Parametre eşleme tablosu oluştur
        param_map = {}
        for i, param in enumerate(self.parameters):
            param_map[param] = arguments[i]
        
        # Makro gövdesini genişlet
        expanded_lines = []
        for line in self.body:
            expanded_line = line
            
            # Parametreleri değiştir - DÜZELTME: Doğru sıralama ve string handling
            for param, arg in param_map.items():
                # 1. String içindeki :param: pattern'ları değiştir - ÖZEL DURUM
                if ':' in expanded_line and '.string' in expanded_line:
                    # STR_3 makrosu için özel işlem: ":p1:" -> argument (tırnak kaldırarak)
                    # Argümandan tırnakları kaldır
                    clean_arg = arg.strip('"\'')
                    expanded_line = expanded_line.replace(f':{param.lower()}:', clean_arg)
                    expanded_line = expanded_line.replace(f':{param.upper()}:', clean_arg)  
                    expanded_line = expanded_line.replace(f':{param}:', clean_arg)
                else:
                    # Normal :param: değiştirme (string dışında)
                    expanded_line = expanded_line.replace(f':{param.lower()}:', arg)
                    expanded_line = expanded_line.replace(f':{param.upper()}:', arg)
                    expanded_line = expanded_line.replace(f':{param}:', arg)
                
                # 2. GNU style: \param
                expanded_line = expanded_line.replace(f'\\{param}', arg)
                
                # 3. Normal kelime sınırları değişimi (son olarak)
                expanded_line = re.sub(rf'\b{re.escape(param)}\b', arg, expanded_line)
            
            # Yerel etiketleri benzersiz yap
            expanded_line = self._make_labels_unique(expanded_line, expansion_id)
            expanded_lines.append(expanded_line)
        
        # Orijinal çağrı satırını oluştur
        original_call = f"{self.name} " + ", ".join(arguments)
        
        return MacroExpansion(self.name, arguments, expanded_lines, original_call, call_line)
    
    def _make_labels_unique(self, line: str, expansion_id: int) -> str:
        """Yerel etiketleri benzersiz yap"""
        # ?? ile başlayan etiketleri değiştir
        if '??' in line:
            unique_suffix = f"_{self.name}_{expansion_id}_{self.call_count}"
            line = line.replace('??', f'_LOCAL{unique_suffix}')
        return line
    
    def get_definition_text(self) -> List[str]:
        """Makro tanımının tam metnini döndür"""
        lines = [f".macro {self.name}" + (f" {', '.join(self.parameters)}" if self.parameters else "")]
        lines.extend(self.body)
        lines.append(".endm")
        return lines

class MacroProcessor:
    """MSP430 Makro İşlemcisi - Tam Düzeltilmiş Versiyon"""
    
    def __init__(self):
        self.macros: Dict[str, MacroDefinition] = {}
        self.assignments: Dict[str, str] = {}  # .asg direktifi için
        self.evaluations: Dict[str, int] = {}  # .eval direktifi için
        self.conditionals_stack: List[bool] = []  # .if/.endif yığını
        self.macro_libraries: List[str] = []  # .mlib dosyaları
        self.expansion_counter = 0  # Makro genişletme sayacı
        self.expansions: List[MacroExpansion] = []  # Tüm makro genişletmeleri
        
        # Makro işleme durumu
        self.in_macro_definition = False
        self.current_macro_def = None
        self.in_loop_definition = False
        self.current_loop_def = None
        self.skip_lines = False  # .if/.endif için
        
        # Makro listing kontrolü
        self.macro_listing_enabled = True  # .mlist/.mnolist kontrolü
        
        # Makro direktifleri
        self.MACRO_DIRECTIVES = {
            '.macro', '.endm', '.asg', '.eval', '.loop', '.endloop',
            '.if', '.else', '.endif', '.mlib', '.mlist', '.mnolist'
        }
    
    def is_macro_directive(self, directive: str) -> bool:
        """Direktifin makro direktifi olup olmadığını kontrol et"""
        return directive.lower() in self.MACRO_DIRECTIVES
    
    def is_macro_call(self, token: str) -> bool:
        """Token'ın makro çağrısı olup olmadığını kontrol et"""
        result = token in self.macros
        if result:
            print(f"DEBUG: Makro çağrısı tespit edildi: {token}")
        return result
    
    def process_line(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """Satırı işle ve genişletilmiş satırları + makro bilgisini döndür"""
        original_line = line
        line = line.strip()
        
        # Debug için
        if line and not line.startswith(';'):
            print(f"DEBUG: İşlenen satır {line_num}: '{line}'")
        
        # Boş satırları ve yorumları geç
        if not line or line.startswith(';'):
            if self.in_macro_definition:
                if line:  # Boş olmayan yorum satırlarını makro gövdesine ekle
                    self.current_macro_def.body.append(original_line)
                return [], None
            elif self.in_loop_definition:
                if line:
                    self.current_loop_def['body'].append(original_line)
                return [], None
            elif self.skip_lines:
                return [], None
            else:
                return [original_line], None
        
        # Önce .asg değişimlerini yap
        line = self._substitute_assignments(line)
        
        # Direktif kontrolü
        parts = line.split()
        if not parts:
            return [original_line] if not self.skip_lines else [], None
        
        directive = parts[0].lower()
        
        # Makro tanımı içinde miyiz?
        if self.in_macro_definition:
            if directive == '.endm':
                # Makro tanımını bitir
                print(f"DEBUG: Makro tanımı tamamlandı: {self.current_macro_def.name}")
                self.macros[self.current_macro_def.name] = self.current_macro_def
                self.in_macro_definition = False
                self.current_macro_def = None
                return [], None
            else:
                # Makro gövdesine satır ekle
                self.current_macro_def.body.append(original_line)
                return [], None
        
        # Loop tanımı içinde miyiz?
        if self.in_loop_definition:
            if directive == '.endloop':
                # Loop'u genişlet ve ekle
                expanded = self._expand_loop()
                self.in_loop_definition = False
                self.current_loop_def = None
                return expanded, None
            else:
                # Loop gövdesine satır ekle
                self.current_loop_def['body'].append(original_line)
                return [], None
        
        # Koşullu derleme kontrolü
        if self.skip_lines and directive not in ['.else', '.endif']:
            return [], None
        
        # Direktif işleme
        if directive == '.macro':
            return self._process_macro_definition(line, line_num)
        
        elif directive == '.asg':
            return self._process_asg(line, line_num)
        
        elif directive == '.eval':
            return self._process_eval(line, line_num)
        
        elif directive == '.loop':
            return self._process_loop(line, line_num)
        
        elif directive == '.if':
            return self._process_if(line, line_num)
        
        elif directive == '.else':
            return self._process_else(line, line_num)
        
        elif directive == '.endif':
            return self._process_endif(line, line_num)
        
        elif directive == '.mlib':
            return self._process_mlib(line, line_num)
        
        elif directive == '.mlist':
            self.macro_listing_enabled = True
            return [], None
        
        elif directive == '.mnolist':
            self.macro_listing_enabled = False
            return [], None
        
        # Makro çağrısı kontrolü
        elif self.is_macro_call(parts[0]):
            print(f"DEBUG: Makro çağrısı işleniyor: {parts[0]} (satır {line_num})")
            return self._expand_macro(line, line_num)
        
        # Normal satır
        else:
            return [original_line], None
    
    def _substitute_assignments(self, line: str) -> str:
        """Satırda .asg atamalarını değiştir"""
        for symbol, value in self.assignments.items():
            # Kelime sınırları ile değiştir
            line = re.sub(rf'\b{re.escape(symbol)}\b', value, line)
        return line
    
    def _process_macro_definition(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """Makro tanımını işle"""
        # .macro name param1, param2, param3
        parts = line.split(None, 2)  # En fazla 3 parça: .macro, name, params
        if len(parts) < 2:
            raise SyntaxError(f"Satır {line_num}: .macro direktifi için makro adı gerekli")
        
        # Makro ismini temizle - virgül ve diğer karakterleri kaldır
        macro_name = parts[1].rstrip(',').strip()
        print(f"DEBUG: Makro tanımı başlatılıyor: {macro_name}")
        
        # Parametreleri parse et
        if len(parts) > 2:
            params_str = parts[2]
            # Virgül ile ayrılmış parametreler
            parameters = [p.strip() for p in params_str.split(',') if p.strip()]
        else:
            parameters = []
        
        print(f"DEBUG: Makro parametreleri: {parameters}")
        
        # Makro tanımını başlat
        self.current_macro_def = MacroDefinition(macro_name, parameters, [], line_num)
        self.in_macro_definition = True
        
        return [], None  # Makro tanımı satırını çıktıdan çıkar
    
    def _process_asg(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """.asg direktifini işle: .asg "value", symbol"""
        parts = line.split(None, 1)  # .asg ve geri kalanı
        if len(parts) != 2:
            raise SyntaxError(f"Satır {line_num}: .asg direktifi hatalı format")
        
        asg_params = parts[1]
        
        # Virgül ile böl
        if ',' in asg_params:
            value_part, symbol_part = [p.strip() for p in asg_params.split(',', 1)]
        else:
            raise SyntaxError(f"Satır {line_num}: .asg direktifi: .asg value, symbol")
        
        # Tırnak işaretlerini kaldır
        if value_part.startswith('"') and value_part.endswith('"'):
            value = value_part[1:-1]
        elif value_part.startswith("'") and value_part.endswith("'"):
            value = value_part[1:-1]
        else:
            value = value_part
        
        symbol = symbol_part
        
        self.assignments[symbol] = value
        print(f"DEBUG: .asg atama: {symbol} = {value}")
        return [], None  # .asg satırını çıktıdan çıkar
    
    def _process_eval(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """.eval direktifini işle: .eval expression, symbol - DÜZELTME: Integer dönüştürme"""
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise SyntaxError(f"Satır {line_num}: .eval direktifi hatalı format")
        
        eval_params = parts[1]
        
        if ',' in eval_params:
            expression, symbol = [p.strip() for p in eval_params.split(',', 1)]
        else:
            raise SyntaxError(f"Satır {line_num}: .eval direktifi: .eval expression, symbol")
        
        try:
            # Önce assignments'ları değiştir
            expression = self._substitute_assignments(expression)
            
            # Matematiksel ifadeleri değerlendir - ÇARPMA VE BÖLME DESTEĞİ
            result = self._evaluate_math_expression(expression)
            
            # DÜZELTME: Kesinlikle integer'a dönüştür
            result = int(result)
            self.assignments[symbol] = str(result)
            print(f"DEBUG: .eval değerlendirme: {symbol} = {result}")
            
        except Exception as e:
            raise SyntaxError(f"Satır {line_num}: .eval ifadesi değerlendirilemedi: {expression} ({e})")
        
        return [], None
    
    def _evaluate_math_expression(self, expression: str) -> float:
        """Matematiksel ifadeyi değerlendir - ÇARPMA VE BÖLME DESTEĞI"""
        # Güvenli matematik değerlendirme
        expression = expression.strip()
        
        # Hex değerleri decimal'e çevir
        if '0x' in expression.lower():
            hex_pattern = re.compile(r'0x([0-9a-fA-F]+)')
            def hex_replacer(match):
                return str(int(match.group(1), 16))
            expression = hex_pattern.sub(hex_replacer, expression)
        
        # Sadece güvenli karakterlere izin ver
        if re.match(r'^[0-9+\-*/() \t]+$', expression):
            try:
                result = eval(expression)
                return float(result)
            except:
                raise ValueError(f"Geçersiz matematik ifadesi: {expression}")
        else:
            raise ValueError(f"Güvenli olmayan karakterler: {expression}")
    
    def _process_loop(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """.loop direktifini işle"""
        parts = line.split()
        if len(parts) != 2:
            raise SyntaxError(f"Satır {line_num}: .loop direktifi: .loop count")
        
        count_expr = parts[1]
        
        try:
            # Önce assignments'ları değiştir
            count_expr = self._substitute_assignments(count_expr)
            count = int(self._evaluate_math_expression(count_expr))
        except:
            raise SyntaxError(f"Satır {line_num}: .loop sayısı geçersiz: {count_expr}")
        
        # Loop tanımını başlat
        self.current_loop_def = {'count': count, 'body': []}
        self.in_loop_definition = True
        
        return [], None
    
    def _expand_loop(self) -> List[str]:
        """Loop'u genişlet"""
        expanded_lines = []
        count = self.current_loop_def['count']
        body = self.current_loop_def['body']
        
        for i in range(count):
            for line in body:
                # Loop içindeki yerel değişkenleri değiştir
                expanded_line = line.replace('??LOOP_INDEX??', str(i))
                expanded_lines.append(expanded_line)
        
        return expanded_lines
    
    def _process_if(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """.if direktifini işle"""
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise SyntaxError(f"Satır {line_num}: .if direktifi için koşul gerekli")
        
        condition = parts[1].strip()
        
        try:
            # Önce assignments'ları değiştir
            condition = self._substitute_assignments(condition)
            
            # Basit koşulları değerlendir
            # Sembol tanımlı mı kontrolü
            if condition in self.assignments:
                result = True
            # Sayısal değerlendirme
            elif re.match(r'^[0-9+\-*/() ]+$', condition):
                result = bool(self._evaluate_math_expression(condition))
            # String karşılaştırması
            elif '==' in condition:
                left, right = condition.split('==', 1)
                left = left.strip().strip('"\'')
                right = right.strip().strip('"\'')
                result = left == right
            elif '!=' in condition:
                left, right = condition.split('!=', 1)
                left = left.strip().strip('"\'')
                right = right.strip().strip('"\'')
                result = left != right
            else:
                # Bilinmeyen koşul, False olarak değerlendir
                result = False
            
            self.conditionals_stack.append(result)
            self.skip_lines = not result
            
        except Exception as e:
            raise SyntaxError(f"Satır {line_num}: .if koşulu değerlendirilemedi: {condition} ({e})")
        
        return [], None
    
    def _process_else(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """.else direktifini işle"""
        if not self.conditionals_stack:
            raise SyntaxError(f"Satır {line_num}: .else direktifi .if olmadan kullanılamaz")
        
        # Koşulu tersine çevir
        self.skip_lines = not self.skip_lines
        
        return [], None
    
    def _process_endif(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """.endif direktifini işle"""
        if not self.conditionals_stack:
            raise SyntaxError(f"Satır {line_num}: .endif direktifi .if olmadan kullanılamaz")
        
        self.conditionals_stack.pop()
        
        # Üst seviye koşul varsa ona göre ayarla
        if self.conditionals_stack:
            self.skip_lines = not self.conditionals_stack[-1]
        else:
            self.skip_lines = False
        
        return [], None
    
    def _process_mlib(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """.mlib direktifini işle"""
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise SyntaxError(f"Satır {line_num}: .mlib direktifi için dosya adı gerekli")
        
        lib_file = parts[1].strip().strip('"\'')
        
        try:
            # Kütüphane dosyasını yükle
            if os.path.exists(lib_file):
                with open(lib_file, 'r', encoding='utf-8') as f:
                    lib_lines = f.readlines()
                
                # Kütüphane dosyasını işle
                expanded_lines = []
                for i, lib_line in enumerate(lib_lines):
                    processed_lines, _ = self.process_line(lib_line.rstrip(), line_num + i)
                    expanded_lines.extend(processed_lines)
                
                self.macro_libraries.append(lib_file)
                return expanded_lines, None
            else:
                print(f"Warning: Makro kütüphanesi bulunamadı: {lib_file}")
                return [], None
        
        except Exception as e:
            raise SyntaxError(f"Satır {line_num}: .mlib dosyası yüklenemedi: {lib_file} ({e})")
    
    def _expand_macro(self, line: str, line_num: int) -> Tuple[List[str], MacroExpansion]:
        """Makro çağrısını genişlet - DÜZELTME: Sonsuz döngü problemi çözüldü"""
        # DÜZELTME: Argüman parse etmeyi düzelt
        # Önce yorumları ayır
        comment = ""
        if ';' in line:
            line_parts = line.split(';', 1)
            line = line_parts[0].strip()
            comment = line_parts[1].strip()
        
        parts = line.split(None, 1)
        macro_name = parts[0]
        
        print(f"DEBUG: _expand_macro çağrıldı: {macro_name}")
        
        if macro_name not in self.macros:
            raise SyntaxError(f"Satır {line_num}: Tanımlanmamış makro: {macro_name}")
        
        macro_def = self.macros[macro_name]
        
        # Argümanları parse et - DÜZELTME: Daha dikkatli parse
        if len(parts) > 1:
            args_str = parts[1]
            # Virgül ile ayrılmış argümanlar - boşlukları koruyarak parse et
            arguments = []
            current_arg = ""
            paren_level = 0
            quote_char = None
            
            for char in args_str:
                if quote_char:
                    current_arg += char
                    if char == quote_char:
                        quote_char = None
                elif char in ['"', "'"]:
                    quote_char = char
                    current_arg += char
                elif char == '(':
                    paren_level += 1
                    current_arg += char
                elif char == ')':
                    paren_level -= 1
                    current_arg += char
                elif char == ',' and paren_level == 0:
                    arguments.append(current_arg.strip())
                    current_arg = ""
                else:
                    current_arg += char
            
            if current_arg.strip():
                arguments.append(current_arg.strip())
        else:
            arguments = []
        
        print(f"DEBUG: Makro argümanları: {arguments}")
        
        try:
            # Makroyu genişlet (.mnolist durumuna bakılmaksızın expand et)
            self.expansion_counter += 1
            expansion = macro_def.expand(arguments, self.expansion_counter, line_num)
            
            # Genişletmeyi kaydet
            self.expansions.append(expansion)
            
            # DÜZELTME: Listing enabled kontrolü kaldırıldı - her zaman genişlet
            # Genişletilmiş satırları tekrar işle (nested makrolar için) - SONSUZ DÖNGÜ KONTROLÜ
            final_lines = []
            for expanded_line in expansion.expanded_lines:
                # DÜZELTME: Sonsuz döngüyü önlemek için makro çağrısı kontrolü yap
                expanded_line_parts = expanded_line.strip().split()
                if expanded_line_parts and expanded_line_parts[0] in self.macros:
                    # İç içe makro çağrısı - bu durumda sadece metni döndür, tekrar işleme
                    final_lines.append(expanded_line)
                else:
                    # Normal satır veya .string gibi direktif
                    processed_lines, nested_expansion = self.process_line(expanded_line, line_num)
                    final_lines.extend(processed_lines)
                    # İç içe makro genişletmesi varsa onları da kaydet
                    if nested_expansion:
                        self.expansions.append(nested_expansion)
            
            print(f"DEBUG: Makro genişletme tamamlandı: {macro_name}, final_lines: {len(final_lines)}")
            return final_lines, expansion
        
        except ValueError as e:
            raise SyntaxError(f"Satır {line_num}: {e}")
    
    def get_macro_list(self) -> List[str]:
        """Tanımlı makroların listesini döndür"""
        return list(self.macros.keys())
    
    def get_assignments(self) -> Dict[str, str]:
        """Tanımlı atamaların listesini döndür"""
        return self.assignments.copy()
    
    def get_macro_definitions(self) -> Dict[str, MacroDefinition]:
        """Makro tanımlarını döndür"""
        return self.macros.copy()
    
    def get_macro_expansions(self) -> List[MacroExpansion]:
        """Tüm makro genişletmelerini döndür"""
        return self.expansions.copy()
    
    def generate_macro_table(self) -> List[str]:
        """MSP430 formatında makro tablosu oluştur"""
        table = []
        table.append("MACRO TABLE")
        table.append("=" * 60)
        table.append("Name\t\tParameters\t\tDefinition Line\t\tCalls")
        table.append("-" * 60)
        
        for name, macro_def in self.macros.items():
            params = f"({', '.join(macro_def.parameters)})" if macro_def.parameters else "()"
            table.append(f"{name}\t\t{params}\t\t{macro_def.definition_line}\t\t{macro_def.call_count}")
        
        if self.assignments:
            table.append("\nASSIGNMENTS (.asg)")
            table.append("-" * 30)
            for symbol, value in self.assignments.items():
                table.append(f"{symbol}\t= {value}")
        
        return table
    
    def clear_all(self):
        """Tüm makro tanımlarını ve atamaları temizle"""
        self.macros.clear()
        self.assignments.clear()
        self.conditionals_stack.clear()
        self.macro_libraries.clear()
        self.expansions.clear()
        self.expansion_counter = 0
        self.in_macro_definition = False
        self.current_macro_def = None
        self.in_loop_definition = False
        self.current_loop_def = None
        self.skip_lines = False
        self.macro_listing_enabled = True

# Test makroları
def create_test_macros() -> MacroProcessor:
    """Test için örnek makrolar oluştur"""
    processor = MacroProcessor()
    
    # Örnek makro tanımları
    test_macros = """
.asg "R4", TEMP_REG
.asg "100", MAX_COUNT

.macro ADD3, a, b, c
    mov     \\a, R4
    add     \\b, R4
    add     \\c, R4
.endm

.macro DELAY_MS, duration
    .eval \\duration * 250, cycles
    mov     #cycles, R15
??delay_loop:
    dec     R15
    jnz     ??delay_loop
.endm

.macro SET_PORT_BITS, port, bits
    bis.b   #\\bits, &\\port
.endm
"""
    
    # Test makrolarını işle
    for i, line in enumerate(test_macros.strip().split('\n')):
        processor.process_line(line, i + 1)
    
    return processor

if __name__ == "__main__":
    # Test kodu
    processor = create_test_macros()
    
    print("Tanımlı makrolar:")
    for macro in processor.get_macro_list():
        print(f"  {macro}")
    
    print("\nTanımlı atamalar:")
    for symbol, value in processor.get_assignments().items():
        print(f"  {symbol} = {value}")
    
    # Test makro çağrıları
    test_calls = [
        "ADD3 val1, val2, val3",
        "DELAY_MS 50",
        "SET_PORT_BITS P1DIR, 0xFF"
    ]
    
    print("\nMakro genişletme testleri:")
    for i, call in enumerate(test_calls):
        print(f"\nÇağrı: {call}")
        try:
            expanded, expansion = processor.process_line(call, i + 1)
            for line in expanded:
                print(f"  {line}")
            if expansion:
                print(f"  Makro: {expansion.macro_name} genişletildi")
        except Exception as e:
            print(f"  Hata: {e}")
    
    # Makro tablosunu göster
    print("\n" + "\n".join(processor.generate_macro_table()))