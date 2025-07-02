#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSP430 G2553 Assembler GUI
MSP430 assembly kodlarını düzenlemek, derlemek ve çalıştırmak için grafik arayüz
"""

import sys
import os
import subprocess
import tempfile
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QTextEdit, QPushButton, QLabel, 
                            QFileDialog, QTabWidget, QSplitter, QMessageBox,
                            QAction, QToolBar, QStatusBar, QLineEdit)
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter, QTextCursor
from PyQt5.QtCore import Qt, QRegExp

# main.py'den Assembler sınıfını ve gerekli sabitleri import et
from main import Assembler, OPTAB, DIRECTIVES, REGISTERS

class MSP430Highlighter(QSyntaxHighlighter):
    """MSP430 assembly kodu için sözdizimi vurgulayıcı"""
    
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
        
        # Komutlar (main.py'deki OPTAB'dan alınıyor)
        opcodes = list(OPTAB.keys())
        
        # Direktifler (main.py'deki DIRECTIVES'den alınıyor)
        directives = list(DIRECTIVES.keys())
        
        # Registerlar (main.py'deki REGISTERS'dan alınıyor)
        registers = list(REGISTERS.keys())
        
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
        
        # Registerlar için kurallar ekle
        for register in registers:
            pattern = QRegExp("\\b" + register + "\\b")
            rule = (pattern, registerFormat)
            self.highlightingRules.append(rule)
        
        # Sayılar için kurallar ekle (ondalık ve hex)
        self.highlightingRules.append((QRegExp("\\b[0-9]+\\b"), numberFormat))
        self.highlightingRules.append((QRegExp("\\b0x[0-9A-Fa-f]+\\b"), numberFormat))
        
        # Yorumlar için kural ekle
        self.highlightingRules.append((QRegExp(";.*"), commentFormat))
        
        # Etiketler için kural ekle (satır başında, : ile biten veya boşlukla devam eden)
        self.highlightingRules.append((QRegExp("^[A-Za-z][A-Za-z0-9_]*:"), labelFormat))
        self.highlightingRules.append((QRegExp("^[A-Za-z][A-Za-z0-9_]*\\s+"), labelFormat))
    
    def highlightBlock(self, text):
        """Metni vurgula"""
        for pattern, format in self.highlightingRules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

class AssemblerGUI(QMainWindow):
    """MSP430 Assembler için grafik kullanıcı arayüzü"""
    
    def __init__(self):
        super(AssemblerGUI, self).__init__()
        
        self.current_file = None
        self.assembler = Assembler()
        
        self.init_ui()
    
    def init_ui(self):
        """Kullanıcı arayüzünü başlat"""
        self.setWindowTitle("MSP430 G2553 Assembler")
        self.setGeometry(100, 100, 1200, 800)
        
        # Ana widget ve layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Menü çubuğu
        menubar = self.menuBar()
        
        # Dosya menüsü
        file_menu = menubar.addMenu("Dosya")
        
        new_action = QAction("Yeni", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self.new_file)
        file_menu.addAction(new_action)
        
        open_action = QAction("Aç", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        save_action = QAction("Kaydet", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_file)
        file_menu.addAction(save_action)
        
        save_as_action = QAction("Farklı Kaydet", self)
        save_as_action.setShortcut("Ctrl+Shift+S")
        save_as_action.triggered.connect(self.save_file_as)
        file_menu.addAction(save_as_action)
        
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
        
        assemble_action = QAction("Derle", self)
        assemble_action.setShortcut("F5")
        assemble_action.triggered.connect(self.assemble_code)
        assembler_menu.addAction(assemble_action)
        
        # Araç çubuğu
        toolbar = QToolBar("Ana Araç Çubuğu")
        self.addToolBar(toolbar)
        
        toolbar.addAction(new_action)
        toolbar.addAction(open_action)
        toolbar.addAction(save_action)
        toolbar.addSeparator()
        toolbar.addAction(assemble_action)
        
        # Splitter oluştur (editör ve çıktı arasında)
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter)
        
        # Editör widget'ı
        editor_widget = QWidget()
        editor_layout = QVBoxLayout(editor_widget)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        
        # Editör
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Courier New", 10))
        self.editor.setLineWrapMode(QTextEdit.NoWrap)
        
        # Sözdizimi vurgulayıcı
        self.highlighter = MSP430Highlighter(self.editor.document())
        
        editor_layout.addWidget(self.editor)
        
        # Çıktı widget'ı
        output_widget = QWidget()
        output_layout = QVBoxLayout(output_widget)
        output_layout.setContentsMargins(0, 0, 0, 0)
        
        # Çıktı sekmeleri
        self.output_tabs = QTabWidget()
        
        # Konsol çıktısı
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Courier New", 10))
        self.output_tabs.addTab(self.console_output, "Konsol")
        
        # Listeleme çıktısı
        self.listing_output = QTextEdit()
        self.listing_output.setReadOnly(True)
        self.listing_output.setFont(QFont("Courier New", 10))
        self.output_tabs.addTab(self.listing_output, "Listeleme")
        
        # Sembol tablosu çıktısı
        self.symbol_output = QTextEdit()
        self.symbol_output.setReadOnly(True)
        self.symbol_output.setFont(QFont("Courier New", 10))
        self.output_tabs.addTab(self.symbol_output, "Sembol Tablosu")
        
        # Nesne kodu çıktısı
        self.object_output = QTextEdit()
        self.object_output.setReadOnly(True)
        self.object_output.setFont(QFont("Courier New", 10))
        self.output_tabs.addTab(self.object_output, "Nesne Kodu")
        
        output_layout.addWidget(self.output_tabs)
        
        # Splitter'a widget'ları ekle
        splitter.addWidget(editor_widget)
        splitter.addWidget(output_widget)
        splitter.setSizes([600, 200])  # Başlangıç boyutları
        
        # Durum çubuğu
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Hazır")
        
        # Örnek kod yükle
        self.load_example_code()
    
    def load_example_code(self):
        """Örnek bir assembly kodu yükle"""
        example_code = """;-------------------------------------------------------------------------------
; MSP430 iki sayı toplama programı örneği
; İşlev: İki sayıyı toplar ve sonucu bir registera kaydeder
; Giriş: R4'te ilk sayı, R5'te ikinci sayı
; Çıkış: R6'da toplam değer, P1OUT'ta toplam değerin düşük byte'ı görüntülenir
;-------------------------------------------------------------------------------

.cdecls C,LIST,"msp430.h"        ; MSP430 tanımlamaları dahil et
.def RESET                       ; Linker için RESET sembolünü tanımla

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
        ; P1 portunu çıkış olarak ayarla (sonucu görüntülemek için)
        bis.b   #0xFF, &P1DIR            ; P1 portunu çıkış olarak ayarla
        
        ; İlk sayıyı R4'e yükle
        mov.w   #5, R4                   ; İlk sayı = 5
        
        ; İkinci sayıyı R5'e yükle
        mov.w   #7, R5                   ; İkinci sayı = 7
        
        ; İki sayıyı topla ve sonucu R6'ya kaydet
        mov.w   R4, R6                   ; R6 = R4
        add.w   R5, R6                   ; R6 = R6 + R5
        
        ; Sonucun düşük byte'ını P1OUT portuna gönder (LED'lerde göstermek için)
        mov.b   R6, &P1OUT               ; P1OUT = düşük byte değeri
        
        ; Sonsuz döngü (programın sonunda bekle)
        jmp     $                        ; Sonsuz döngü

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
            self.statusBar.showMessage("Yeni dosya oluşturuldu")
    
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
                    self.statusBar.showMessage(f"Dosya açıldı: {file_name}")
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
            self.statusBar.showMessage(f"Dosya kaydedildi: {file_name}")
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
    
    def assemble_code(self):
        """Kodu derle"""
        # Önce dosyayı kaydet
        if not self.save_file():
            return
        
        self.console_output.clear()
        self.listing_output.clear()
        self.symbol_output.clear()
        self.object_output.clear()
        
        self.statusBar.showMessage("Derleniyor...")
        
        try:
            # Assembler nesnesini oluştur
            self.assembler = Assembler()
            
            # Pass 1'i çalıştır
            if self.assembler.pass1(self.current_file):
                # Pass 2'yi çalıştır
                if self.assembler.pass2():
                    # Çıktı dosyalarını oluştur
                    output_prefix = os.path.splitext(self.current_file)[0]
                    self.assembler.write_output(output_prefix)
                    
                    # Çıktıları göster
                    self.show_outputs(output_prefix)
                    
                    self.statusBar.showMessage("Derleme başarılı")
                else:
                    self.console_output.append("Pass 2 sırasında hatalar oluştu. Çıktı dosyaları oluşturulmadı.")
                    self.statusBar.showMessage("Derleme hatası")
            else:
                self.console_output.append("Pass 1 sırasında hatalar oluştu. Pass 2 çalıştırılmadı.")
                self.statusBar.showMessage("Derleme hatası")
        
        except Exception as e:
            self.console_output.append(f"Derleme sırasında hata oluştu: {str(e)}")
            self.statusBar.showMessage("Derleme hatası")
    
    def show_outputs(self, output_prefix):
        """Çıktı dosyalarını göster"""
        # Listeleme dosyasını göster
        try:
            with open(f"{output_prefix}.lst", 'r') as f:
                self.listing_output.setPlainText(f.read())
        except:
            self.listing_output.setPlainText("Listeleme dosyası okunamadı.")
        
        # Sembol tablosunu göster
        try:
            with open(f"{output_prefix}.sym", 'r') as f:
                self.symbol_output.setPlainText(f.read())
        except:
            self.symbol_output.setPlainText("Sembol tablosu dosyası okunamadı.")
        
        # Nesne kodunu göster
        try:
            with open(f"{output_prefix}.obj", 'r') as f:
                self.object_output.setPlainText(f.read())
        except:
            self.object_output.setPlainText("Nesne kodu dosyası okunamadı.")
        
        # Konsola özet bilgileri yaz
        self.console_output.append(f"Derleme başarılı.")
        self.console_output.append(f"Program uzunluğu: {self.assembler.program_length} byte")
        self.console_output.append(f"Başlangıç adresi: 0x{self.assembler.starting_address:04X}")
        self.console_output.append(f"Sembol sayısı: {len(self.assembler.symtab)}")
        self.console_output.append(f"\nÇıktı dosyaları oluşturuldu:")
        self.console_output.append(f"- {output_prefix}.lst (Listeleme dosyası)")
        self.console_output.append(f"- {output_prefix}.sym (Sembol tablosu)")
        self.console_output.append(f"- {output_prefix}.obj (Nesne kodu)")

def main():
    app = QApplication(sys.argv)
    window = AssemblerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 