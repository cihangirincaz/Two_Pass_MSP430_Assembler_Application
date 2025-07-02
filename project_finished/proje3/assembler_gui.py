#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSP430 G2553 Assembler GUI - Güncellenmiş Versiyon
MSP430 assembly kodlarını düzenlemek, derlemek ve çalıştırmak için grafik arayüz
Makro sistemi desteği dahil
"""

import sys
import os
import subprocess
import tempfile
try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QTextEdit, QPushButton, QLabel, 
                                QFileDialog, QTabWidget, QSplitter, QMessageBox,
                                QAction, QToolBar, QStatusBar, QLineEdit, QProgressBar)
    from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter, QTextCursor
    from PyQt5.QtCore import Qt, QRegExp, QThread, pyqtSignal
    PYQT5_AVAILABLE = True
    print("✓ PyQt5 başarıyla yüklendi")
except ImportError as e:
    print(f"PyQt5 import hatası: {e}")
    print("PyQt5 kurulu olmayabilir. Kurmak için: pip install PyQt5")
    
    try:
        # PySide2 alternatifini dene
        from PySide2.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                    QHBoxLayout, QTextEdit, QPushButton, QLabel, 
                                    QFileDialog, QTabWidget, QSplitter, QMessageBox,
                                    QAction, QToolBar, QStatusBar, QLineEdit, QProgressBar)
        from PySide2.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter, QTextCursor
        from PySide2.QtCore import Qt, QRegExp, QThread, Signal as pyqtSignal
        PYQT5_AVAILABLE = True
        print("✓ PySide2 kullanılıyor")
    except ImportError:
        print("Ne PyQt5 ne de PySide2 bulunamadı!")
        print("GUI olmadan çalışmak için main.py'yi kullanın: python main.py dosya.asm")
        sys.exit(1)

# main.py'den Assembler sınıfını ve gerekli sabitleri import et
try:
    from main import Assembler, OPTAB, DIRECTIVES, REGISTERS
    from macro import MacroProcessor
except ImportError as e:
    print(f"Import hatası: {e}")
    print("main.py ve macro.py dosyalarının aynı dizinde olduğundan emin olun.")
    sys.exit(1)

class MSP430Highlighter(QSyntaxHighlighter):
    """MSP430 assembly kodu için sözdizimi vurgulayıcı - Makro desteği ile"""
    
    def __init__(self, parent=None):
        super(MSP430Highlighter, self).__init__(parent)
        
        self.highlightingRules = []
        
        # Komutlar için format
        opcodeFormat = QTextCharFormat()
        opcodeFormat.setForeground(QColor("#0000FF"))  # Mavi
        opcodeFormat.setFontWeight(QFont.Bold)
        
        # Direktifler için format
        directiveFormat = QTextCharFormat()
        directiveFormat.setForeground(QColor("#800080"))  # Mor
        directiveFormat.setFontWeight(QFont.Bold)
        
        # Makro direktifleri için format
        macroDirectiveFormat = QTextCharFormat()
        macroDirectiveFormat.setForeground(QColor("#FF1493"))  # DeepPink
        macroDirectiveFormat.setFontWeight(QFont.Bold)
        
        # Registerlar için format
        registerFormat = QTextCharFormat()
        registerFormat.setForeground(QColor("#008000"))  # Yeşil
        
        # Sayılar için format
        numberFormat = QTextCharFormat()
        numberFormat.setForeground(QColor("#FF8C00"))  # Turuncu
        
        # Yorumlar için format
        commentFormat = QTextCharFormat()
        commentFormat.setForeground(QColor("#808080"))  # Gri
        commentFormat.setFontItalic(True)
        
        # Etiketler için format
        labelFormat = QTextCharFormat()
        labelFormat.setForeground(QColor("#B22222"))  # Kırmızı
        labelFormat.setFontWeight(QFont.Bold)
        
        # String literal'lar için format
        stringFormat = QTextCharFormat()
        stringFormat.setForeground(QColor("#008080"))  # Teal
        
        # Komutlar (main.py'deki OPTAB'dan alınıyor)
        opcodes = list(OPTAB.keys())
        
        # Direktifler (main.py'deki DIRECTIVES'den alınıyor)
        directives = list(DIRECTIVES.keys())
        
        # Registerlar (main.py'deki REGISTERS'dan alınıyor)
        registers = list(REGISTERS.keys())
        
        # Makro direktifleri
        macro_directives = ['.macro', '.endm', '.asg', '.eval', '.loop', '.endloop',
                           '.if', '.else', '.endif', '.mlib', '.mlist', '.mnolist']
        
        # Komutlar için kurallar ekle
        for opcode in opcodes:
            pattern = QRegExp("\\b" + opcode + "\\b")
            rule = (pattern, opcodeFormat)
            self.highlightingRules.append(rule)
        
        # Direktifler için kurallar ekle
        for directive in directives:
            pattern = QRegExp("\\b" + directive + "\\b")
            rule = (pattern, directiveFormat)
            self.highlightingRules.append(rule)
        
        # Makro direktifleri için kurallar ekle
        for macro_dir in macro_directives:
            pattern = QRegExp("\\b" + macro_dir + "\\b")
            rule = (pattern, macroDirectiveFormat)
            self.highlightingRules.append(rule)
        
        # Registerlar için kurallar ekle
        for register in registers:
            pattern = QRegExp("\\b" + register + "\\b")
            rule = (pattern, registerFormat)
            self.highlightingRules.append(rule)
        
        # String literal'lar için kurallar ekle
        self.highlightingRules.append((QRegExp('".*"'), stringFormat))
        self.highlightingRules.append((QRegExp("'.*'"), stringFormat))
        
        # Sayılar için kurallar ekle (ondalık ve hex)
        self.highlightingRules.append((QRegExp("\\b[0-9]+\\b"), numberFormat))
        self.highlightingRules.append((QRegExp("\\b0x[0-9A-Fa-f]+\\b"), numberFormat))
        self.highlightingRules.append((QRegExp("#[0-9A-Fa-f]+"), numberFormat))  # Immediate değerler
        
        # Yorumlar için kural ekle
        self.highlightingRules.append((QRegExp(";.*"), commentFormat))
        
        # Etiketler için kural ekle (satır başında, : ile biten)
        self.highlightingRules.append((QRegExp("^[A-Za-z][A-Za-z0-9_]*:"), labelFormat))
    
    def highlightBlock(self, text):
        """Metni vurgula"""
        for pattern, format in self.highlightingRules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

class AssemblerThread(QThread):
    """Assembler'ı ayrı thread'de çalıştırmak için"""
    finished = pyqtSignal(bool, str)  # başarı durumu, mesaj
    progress = pyqtSignal(str)  # ilerleme mesajı
    
    def __init__(self, input_file):
        super().__init__()
        self.input_file = input_file
        
    def run(self):
        try:
            self.progress.emit("Assembler başlatılıyor...")
            assembler = Assembler()
            
            self.progress.emit("Pass 1 çalıştırılıyor...")
            if assembler.pass1(self.input_file):
                self.progress.emit("Pass 2 çalıştırılıyor...")
                if assembler.pass2():
                    self.progress.emit("Çıktı dosyaları oluşturuluyor...")
                    output_prefix = os.path.splitext(self.input_file)[0]
                    assembler.write_output(output_prefix)
                    
                    # Makro istatistikleri
                    macros = assembler.macro_processor.get_macro_list()
                    macro_count = len(macros)
                    expansion_count = len(assembler.macro_expansions)
                    
                    message = f"Derleme başarılı!\n"
                    message += f"Program uzunluğu: {assembler.program_length} byte\n"
                    message += f"Başlangıç adresi: 0x{assembler.starting_address:04X}\n"
                    message += f"Sembol sayısı: {len(assembler.symtab)}\n"
                    if macro_count > 0:
                        message += f"Makro sayısı: {macro_count}\n"
                        message += f"Makro genişletmesi: {expansion_count}\n"
                    
                    self.finished.emit(True, message)
                else:
                    self.finished.emit(False, "Pass 2 sırasında hatalar oluştu.")
            else:
                self.finished.emit(False, "Pass 1 sırasında hatalar oluştu.")
                
        except Exception as e:
            self.finished.emit(False, f"Derleme sırasında hata: {str(e)}")

class AssemblerGUI(QMainWindow):
    """MSP430 Assembler için grafik kullanıcı arayüzü - Makro sistemi desteği ile"""
    
    def __init__(self):
        super(AssemblerGUI, self).__init__()
        
        self.current_file = None
        self.assembler = None
        self.assembler_thread = None
        
        self.init_ui()
    
    def init_ui(self):
        """Kullanıcı arayüzünü başlat"""
        self.setWindowTitle("MSP430 G2553 Assembler - Makro Sistemi Desteği")
        self.setGeometry(100, 100, 1400, 900)
        
        # Ana widget ve layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Menü çubuğu
        self.create_menus()
        
        # Araç çubuğu
        self.create_toolbar()
        
        # Splitter oluştur (editör ve çıktı arasında)
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter)
        
        # Editör widget'ı
        editor_widget = self.create_editor_widget()
        
        # Çıktı widget'ı
        output_widget = self.create_output_widget()
        
        # Splitter'a widget'ları ekle
        splitter.addWidget(editor_widget)
        splitter.addWidget(output_widget)
        splitter.setSizes([600, 300])  # Başlangıç boyutları
        
        # Durum çubuğu
        self.create_status_bar()
        
        # Örnek kod yükle
        self.load_example_code()
    
    def create_menus(self):
        """Menü çubuğunu oluştur"""
        menubar = self.menuBar()
        
        # Dosya menüsü
        file_menu = menubar.addMenu("Dosya")
        
        self.new_action = QAction("Yeni", self)
        self.new_action.setShortcut("Ctrl+N")
        self.new_action.triggered.connect(self.new_file)
        file_menu.addAction(self.new_action)
        
        self.open_action = QAction("Aç", self)
        self.open_action.setShortcut("Ctrl+O")
        self.open_action.triggered.connect(self.open_file)
        file_menu.addAction(self.open_action)
        
        self.save_action = QAction("Kaydet", self)
        self.save_action.setShortcut("Ctrl+S")
        self.save_action.triggered.connect(self.save_file)
        file_menu.addAction(self.save_action)
        
        self.save_as_action = QAction("Farklı Kaydet", self)
        self.save_as_action.setShortcut("Ctrl+Shift+S")
        self.save_as_action.triggered.connect(self.save_file_as)
        file_menu.addAction(self.save_as_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Çıkış", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Düzenle menüsü
        edit_menu = menubar.addMenu("Düzenle")
        
        undo_action = QAction("Geri Al", self)
        undo_action.setShortcut("Ctrl+Z")
        undo_action.triggered.connect(lambda: self.editor.undo())
        edit_menu.addAction(undo_action)
        
        redo_action = QAction("Yinele", self)
        redo_action.setShortcut("Ctrl+Y")
        redo_action.triggered.connect(lambda: self.editor.redo())
        edit_menu.addAction(redo_action)
        
        edit_menu.addSeparator()
        
        cut_action = QAction("Kes", self)
        cut_action.setShortcut("Ctrl+X")
        cut_action.triggered.connect(lambda: self.editor.cut())
        edit_menu.addAction(cut_action)
        
        copy_action = QAction("Kopyala", self)
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(lambda: self.editor.copy())
        edit_menu.addAction(copy_action)
        
        paste_action = QAction("Yapıştır", self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(lambda: self.editor.paste())
        edit_menu.addAction(paste_action)
        
        # Assembler menüsü
        assembler_menu = menubar.addMenu("Assembler")
        
        self.assemble_action = QAction("Derle (F5)", self)
        self.assemble_action.setShortcut("F5")
        self.assemble_action.triggered.connect(self.assemble_code)
        assembler_menu.addAction(self.assemble_action)
        
        self.validate_syntax_action = QAction("Sözdizimi Kontrolü", self)
        self.validate_syntax_action.setShortcut("F6")
        self.validate_syntax_action.triggered.connect(self.validate_syntax)
        assembler_menu.addAction(self.validate_syntax_action)
        
        # Makro menüsü
        macro_menu = menubar.addMenu("Makro")
        
        insert_macro_action = QAction("Makro Şablonu Ekle", self)
        insert_macro_action.triggered.connect(self.insert_macro_template)
        macro_menu.addAction(insert_macro_action)
        
        show_macros_action = QAction("Tanımlı Makroları Göster", self)
        show_macros_action.triggered.connect(self.show_defined_macros)
        macro_menu.addAction(show_macros_action)
    
    def create_toolbar(self):
        """Araç çubuğunu oluştur"""
        toolbar = QToolBar("Ana Araç Çubuğu")
        self.addToolBar(toolbar)
        
        toolbar.addAction(self.new_action)
        toolbar.addAction(self.open_action)
        toolbar.addAction(self.save_action)
        toolbar.addSeparator()
        toolbar.addAction(self.assemble_action)
        toolbar.addAction(self.validate_syntax_action)
    
    def create_editor_widget(self):
        """Editör widget'ını oluştur"""
        editor_widget = QWidget()
        editor_layout = QVBoxLayout(editor_widget)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        
        # Editör başlığı
        editor_label = QLabel("Assembly Kod Editörü")
        editor_label.setFont(QFont("Arial", 10, QFont.Bold))
        editor_layout.addWidget(editor_label)
        
        # Editör
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Courier New", 11))
        self.editor.setLineWrapMode(QTextEdit.NoWrap)
        
        # Sözdizimi vurgulayıcı
        self.highlighter = MSP430Highlighter(self.editor.document())
        
        editor_layout.addWidget(self.editor)
        
        return editor_widget
    
    def create_output_widget(self):
        """Çıktı widget'ını oluştur"""
        output_widget = QWidget()
        output_layout = QVBoxLayout(output_widget)
        output_layout.setContentsMargins(0, 0, 0, 0)
        
        # Çıktı başlığı
        output_label = QLabel("Assembler Çıktıları")
        output_label.setFont(QFont("Arial", 10, QFont.Bold))
        output_layout.addWidget(output_label)
        
        # Çıktı sekmeleri
        self.output_tabs = QTabWidget()
        
        # Konsol çıktısı
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Courier New", 9))
        self.output_tabs.addTab(self.console_output, "Konsol")
        
        # Listeleme çıktısı
        self.listing_output = QTextEdit()
        self.listing_output.setReadOnly(True)
        self.listing_output.setFont(QFont("Courier New", 9))
        self.output_tabs.addTab(self.listing_output, "Listeleme (.lst)")
        
        # Sembol tablosu çıktısı
        self.symbol_output = QTextEdit()
        self.symbol_output.setReadOnly(True)
        self.symbol_output.setFont(QFont("Courier New", 9))
        self.output_tabs.addTab(self.symbol_output, "Sembol Tablosu (.sym)")
        
        # Nesne kodu çıktısı
        self.object_output = QTextEdit()
        self.object_output.setReadOnly(True)
        self.object_output.setFont(QFont("Courier New", 9))
        self.output_tabs.addTab(self.object_output, "Nesne Kodu (.obj)")
        
        # Makro tablosu çıktısı
        self.macro_output = QTextEdit()
        self.macro_output.setReadOnly(True)
        self.macro_output.setFont(QFont("Courier New", 9))
        self.output_tabs.addTab(self.macro_output, "Makro Tablosu (.mac)")
        
        output_layout.addWidget(self.output_tabs)
        
        return output_widget
    
    def create_status_bar(self):
        """Durum çubuğunu oluştur"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        self.status_bar.showMessage("Hazır")
    
    def load_example_code(self):
        """Makro sistemi örnekli assembly kodu yükle"""
        example_code = """;-------------------------------------------------------------------------------
; MSP430 Makro Sistemi Test Programı - MSP430 Format
; Bu dosya makro sisteminin tüm özelliklerini MSP430 formatında test eder
;-------------------------------------------------------------------------------

.cdecls C,LIST,"msp430.h"        ; MSP430 tanımlamaları dahil et
.def RESET                       ; Linker için RESET sembolünü tanımla

;-------------------------------------------------------------------------------
; Makro atamaları (.asg direktifi) - MSP430 TI format
;-------------------------------------------------------------------------------
.asg "R4", TEMP_REG              ; TEMP_REG artık R4 anlamına gelir
.asg "100", MAX_COUNT            ; Sayısal sabit tanımla
.asg "P1OUT", LED_PORT           ; Port tanımla
.asg "0xFF", ALL_BITS            ; Bit mask tanımla

;-------------------------------------------------------------------------------
; Matematiksel değerlendirmeler (.eval direktifi)
;-------------------------------------------------------------------------------
.eval 10+5, RESULT               ; RESULT = 15
.eval 250, DELAY_COUNT           ; DELAY_COUNT = 250  
.eval 0x20*2, BUFFER_SIZE        ; BUFFER_SIZE = 64

;-------------------------------------------------------------------------------
; Makro tanımları - MSP430 TI format
;-------------------------------------------------------------------------------

; String makrosu - MSP430 formatında test
.macro STR_3, P1, P2, P3
.string ":p1:", ":p2:", ":p3:"
.endm

; Üç sayı toplama makrosu - MSP430 format
.macro ADD3, a, b, c
    mov     a, TEMP_REG          ; İlk parametreyi TEMP_REG'e yükle (TI style)
    add     b, TEMP_REG          ; İkinci parametreyi ekle (TI style)
    add     c, TEMP_REG          ; Üçüncü parametreyi ekle (TI style)
.endm

; Port bit set makrosu - MSP430 format
.macro SET_PORT_BITS, port, bits
    bis.b   #bits, &port         ; Belirtilen bitleri set et (TI style)
.endm

; Gecikme makrosu - MSP430 format
.macro DELAY_MS, duration
    .eval duration * 250 / 1000, cycles ; Döngü sayısını hesapla
    mov     #cycles, R15         ; Sayacı yükle
??delay_loop:
    dec     R15                  ; Sayacı azalt
    jnz     ??delay_loop         ; Sıfır değilse devam et
.endm

;-------------------------------------------------------------------------------
.text                            ; Kod bölümü başlangıcı
.retain                          ; Bölümü tut
.retainrefs                      ; Referansları tut
;-------------------------------------------------------------------------------

; Program başlangıcı
RESET:
        mov.w   #__STACK_END, SP         ; Stack pointer'ı ayarla
        mov.w   #WDTPW | WDTHOLD, &WDTCTL  ; Watchdog Timer'ı durdur

; Ana kod
main:
        ; P1 portunu çıkış olarak ayarla
        SET_PORT_BITS P1DIR, ALL_BITS    ; Makro: Tüm bitleri set et
        
        ; Test değerleri
        mov.w   #5, R5                   ; İlk sayı = 5
        mov.w   #7, R6                   ; İkinci sayı = 7  
        mov.w   #3, R7                   ; Üçüncü sayı = 3
        
        ; String makro testi - MSP430 formatında
        .mnolist                         ; Suppress expansion
        STR_3 "as", "I", "am"           ; Invoke STR_3 macro
        .mlist                           ; Show macro expansion
        
        ; Üç sayıyı topla (makro kullanarak) - MSP430 format
        ADD3    R5, R6, R7               ; Makro: 5 + 7 + 3 = 15, sonuç TEMP_REG'de
        
        ; Sonucu LED port'una gönder
        mov.b   TEMP_REG, &LED_PORT     ; Sonucu LED_PORT'a gönder

; Ana döngü - MSP430 formatında makro kullanımı
forever_loop:
        ; Gecikme makrosu kullanımı
        DELAY_MS 100                     ; 100ms gecikme
        
        ; LED'i toggle et
        xor.b   #0x01, &P1OUT           ; LED'i toggle et
        
        ; Sayaç testi
        mov.w   #MAX_COUNT, R8           ; MAX_COUNT değerini yükle
        dec     R8                       ; Sayacı azalt
        jnz     forever_loop             ; Sıfır değilse devam et

; Test: String makrosunu tekrar çağır - MSP430 format
test_string_again:
        STR_3 "test", "macro", "again"  ; Invoke STR_3 macro again

        ; Başa dön
        jmp     forever_loop

;-------------------------------------------------------------------------------
; Stack ayarlamaları
;-------------------------------------------------------------------------------
.global __STACK_END
.sect   .stack                          ; Stack bölümünü tanımla

;-------------------------------------------------------------------------------
; Kesme vektör tablosu
;-------------------------------------------------------------------------------
.sect   ".reset"                        ; MSP430 reset vektörü
.short  RESET
.end
"""
        self.editor.setPlainText(example_code)
    
    def new_file(self):
        """Yeni dosya oluştur"""
        if self.maybe_save():
            self.editor.clear()
            self.current_file = None
            self.clear_outputs()
            self.status_bar.showMessage("Yeni dosya oluşturuldu")
    
    def open_file(self):
        """Dosya aç"""
        if self.maybe_save():
            file_name, _ = QFileDialog.getOpenFileName(
                self, "Dosya Aç", "", "Assembly Dosyaları (*.asm *.s);;Tüm Dosyalar (*)"
            )
            
            if file_name:
                try:
                    with open(file_name, 'r', encoding='utf-8') as f:
                        self.editor.setPlainText(f.read())
                    
                    self.current_file = file_name
                    self.clear_outputs()
                    self.status_bar.showMessage(f"Dosya açıldı: {file_name}")
                except Exception as e:
                    QMessageBox.critical(self, "Hata", f"Dosya açılırken hata oluştu: {str(e)}")
    
    def save_file(self):
        """Dosyayı kaydet"""
        if self.current_file:
            return self.save_file_to(self.current_file)
        else:
            return self.save_file_as()
    
    def save_file_as(self):
        """Dosyayı farklı kaydet"""
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Dosyayı Kaydet", "", "Assembly Dosyaları (*.asm *.s);;Tüm Dosyalar (*)"
        )
        
        if file_name:
            return self.save_file_to(file_name)
        
        return False
    
    def save_file_to(self, file_name):
        """Dosyayı belirtilen konuma kaydet"""
        try:
            with open(file_name, 'w', encoding='utf-8') as f:
                f.write(self.editor.toPlainText())
            
            self.current_file = file_name
            self.status_bar.showMessage(f"Dosya kaydedildi: {file_name}")
            return True
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dosya kaydedilirken hata oluştu: {str(e)}")
            return False
    
    def maybe_save(self):
        """Değişiklikler varsa kaydetmeyi öner"""
        if not self.editor.document().isModified():
            return True
        
        ret = QMessageBox.warning(
            self, "MSP430 Assembler",
            "Dosya değiştirildi.\nDeğişiklikleri kaydetmek istiyor musunuz?",
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel
        )
        
        if ret == QMessageBox.Save:
            return self.save_file()
        elif ret == QMessageBox.Cancel:
            return False
        
        return True
    
    def clear_outputs(self):
        """Tüm çıktı sekmeleri temizle"""
        self.console_output.clear()
        self.listing_output.clear()
        self.symbol_output.clear()
        self.object_output.clear()
        self.macro_output.clear()
    
    def assemble_code(self):
        """Kodu derle - Thread kullanarak"""
        # Önce dosyayı kaydet
        if not self.current_file:
            if not self.save_file_as():
                return
        else:
            if not self.save_file():
                return
        
        # Çıktıları temizle
        self.clear_outputs()
        
        # UI'yi disable et
        self.assemble_action.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Belirsiz progress
        
        # Assembler thread'ini başlat
        self.assembler_thread = AssemblerThread(self.current_file)
        self.assembler_thread.progress.connect(self.on_assembly_progress)
        self.assembler_thread.finished.connect(self.on_assembly_finished)
        self.assembler_thread.start()
    
    def on_assembly_progress(self, message):
        """Assembler ilerleme mesajı"""
        self.status_bar.showMessage(message)
        self.console_output.append(f">>> {message}")
    
    def on_assembly_finished(self, success, message):
        """Assembler tamamlandı"""
        # UI'yi enable et
        self.assemble_action.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if success:
            self.console_output.append(f"\n✓ {message}")
            self.status_bar.showMessage("Derleme başarılı")
            
            # Çıktı dosyalarını göster
            output_prefix = os.path.splitext(self.current_file)[0]
            self.show_outputs(output_prefix)
        else:
            self.console_output.append(f"\n✗ {message}")
            self.status_bar.showMessage("Derleme hatası")
    
    def validate_syntax(self):
        """Sözdizimi kontrolü yap"""
        self.console_output.append(">>> Sözdizimi kontrolü başlatılıyor...")
        
        try:
            # Basit sözdizimi kontrolü
            lines = self.editor.toPlainText().split('\n')
            errors = []
            
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith(';'):
                    continue
                
                # Basit kontroller
                if line.endswith(':') and ' ' in line:
                    errors.append(f"Satır {i}: Etiket tanımında hata - boşluk içermemeli")
                
                # Makro direktifi kontrolü
                if line.startswith('.macro') and len(line.split()) < 2:
                    errors.append(f"Satır {i}: .macro direktifi için makro adı gerekli")
                
                if line.startswith('.asg') and len(line.split(',')) != 2:
                    errors.append(f"Satır {i}: .asg direktifi format hatası")
            
            if errors:
                self.console_output.append("Sözdizimi hataları bulundu:")
                for error in errors:
                    self.console_output.append(f"  ⚠ {error}")
            else:
                self.console_output.append("✓ Sözdizimi kontrolü başarılı - hata bulunamadı")
                
        except Exception as e:
            self.console_output.append(f"✗ Sözdizimi kontrolü hatası: {str(e)}")
    
    def insert_macro_template(self):
        """Makro şablonu ekle"""
        template = """.macro MACRO_NAME, param1, param2
    ; Makro gövdesi buraya yazılır
    mov     param1, param2
.endm"""
        
        cursor = self.editor.textCursor()
        cursor.insertText(template)
        
        # İmleçi makro adının üzerine götür
        cursor.movePosition(QTextCursor.Left, QTextCursor.MoveAnchor, len(template) - 7)
        cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 10)  # MACRO_NAME'i seç
        self.editor.setTextCursor(cursor)
    
    def show_defined_macros(self):
        """Tanımlı makroları göster"""
        try:
            # Basit makro tespit sistemi
            lines = self.editor.toPlainText().split('\n')
            macros = []
            assignments = []
            
            for line in lines:
                line = line.strip()
                if line.startswith('.macro '):
                    parts = line.split()
                    if len(parts) >= 2:
                        macro_name = parts[1].rstrip(',')
                        params = ', '.join(parts[2:]) if len(parts) > 2 else ""
                        macros.append(f"{macro_name}({params})")
                
                elif line.startswith('.asg '):
                    # .asg "value", symbol formatını parse et
                    try:
                        parts = line.split(',')
                        if len(parts) == 2:
                            value = parts[0].split(None, 1)[1].strip().strip('"\'')
                            symbol = parts[1].strip()
                            assignments.append(f"{symbol} = {value}")
                    except:
                        pass
            
            # Sonuçları konsola yazdır
            self.console_output.append("\n>>> Tanımlı Makrolar:")
            if macros:
                for macro in macros:
                    self.console_output.append(f"  📋 {macro}")
            else:
                self.console_output.append("  (Tanımlı makro bulunamadı)")
            
            self.console_output.append("\n>>> .asg Atamaları:")
            if assignments:
                for assignment in assignments:
                    self.console_output.append(f"  📌 {assignment}")
            else:
                self.console_output.append("  (Tanımlı atama bulunamadı)")
                
        except Exception as e:
            self.console_output.append(f"✗ Makro analizi hatası: {str(e)}")
    
    def show_outputs(self, output_prefix):
        """Çıktı dosyalarını göster"""
        # Listeleme dosyasını göster
        try:
            with open(f"{output_prefix}.lst", 'r', encoding='utf-8') as f:
                self.listing_output.setPlainText(f.read())
        except Exception as e:
            self.listing_output.setPlainText(f"Listeleme dosyası okunamadı: {str(e)}")
        
        # Sembol tablosunu göster
        try:
            with open(f"{output_prefix}.sym", 'r', encoding='utf-8') as f:
                self.symbol_output.setPlainText(f.read())
        except Exception as e:
            self.symbol_output.setPlainText(f"Sembol tablosu dosyası okunamadı: {str(e)}")
        
        # Nesne kodunu göster
        try:
            with open(f"{output_prefix}.obj", 'r', encoding='utf-8') as f:
                self.object_output.setPlainText(f.read())
        except Exception as e:
            self.object_output.setPlainText(f"Nesne kodu dosyası okunamadı: {str(e)}")
        
        # Makro tablosunu göster
        try:
            with open(f"{output_prefix}.mac", 'r', encoding='utf-8') as f:
                self.macro_output.setPlainText(f.read())
        except Exception as e:
            self.macro_output.setPlainText(f"Makro tablosu dosyası okunamadı: {str(e)}")
        
        # Konsola özet bilgileri yaz
        self.console_output.append(f"\n📁 Çıktı dosyaları oluşturuldu:")
        self.console_output.append(f"   • {output_prefix}.lst - Listeleme dosyası")
        self.console_output.append(f"   • {output_prefix}.sym - Sembol tablosu")
        self.console_output.append(f"   • {output_prefix}.obj - Nesne kodu")
        self.console_output.append(f"   • {output_prefix}.mac - Makro tablosu")
        self.console_output.append(f"   • {output_prefix}.o - MSP430 format nesne dosyası")

def main():
    app = QApplication(sys.argv)
    
    # Uygulama stilini ayarla
    app.setStyle('Fusion')
    
    window = AssemblerGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()