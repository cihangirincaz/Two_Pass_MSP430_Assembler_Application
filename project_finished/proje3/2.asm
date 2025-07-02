;-------------------------------------------------------------------------------
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
