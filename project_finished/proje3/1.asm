; MSP430 G2553 Test Program - Macro Demonstration
; Bu program senin assembler'ın için özel yazıldı
; LED blink + Makro kullanımı

.text
.global RESET
.global main

; Makro tanımları
.macro INIT_WDT
    mov.w   #WDTPW|WDTHOLD, &WDTCTL     ; Watchdog'u durdur
.endm

.macro INIT_GPIO
    bis.b   #01h, &P1DIR                 ; P1.0'ı output yap (LED)
    bic.b   #01h, &P1OUT                 ; LED'i söndür
.endm

.macro DELAY_LOOP, cycles
    mov.w   #cycles, R15                 ; Delay counter'ı R15'e yükle
delay_loop:
    dec.w   R15                          ; Counter'ı azalt
    jnz     delay_loop                   ; Sıfır değilse devam et
.endm

.macro TOGGLE_LED
    xor.b   #01h, &P1OUT                 ; P1.0 LED'ini toggle et
.endm

.macro SET_LED, state
    mov.b   #state, &P1OUT               ; LED state'ini ayarla
.endm

; Sabitler
LED_PIN     EQU     01h
DELAY_COUNT EQU     30000

; Ana program başlangıcı
RESET:
    mov.w   #__STACK_END, SP             ; Stack pointer'ı ayarla
    INIT_WDT                             ; Makro: Watchdog durdur
    INIT_GPIO                            ; Makro: GPIO init
    jmp     main                         ; main'e atla

main:
    TOGGLE_LED                           ; Makro: LED'i toggle et
    DELAY_LOOP DELAY_COUNT               ; Makro: Bekle
    jmp     main                         ; Sonsuz döngü

; Test fonksiyonu
test_function:
    SET_LED 01h                          ; Makro: LED'i aç
    DELAY_LOOP 10000                     ; Makro: Kısa bekle
    SET_LED 00h                          ; Makro: LED'i kapat
    ret                                  ; Fonksiyondan dön

; Data section
.data
counter:    .word   0                    ; 16-bit counter
status:     .byte   1                    ; 8-bit status

END

; Data section
.data
message:    BYTE   "Test"
counter:    WORD   0
status:     BYTE   1

; BSS section (uninitialized data)  
.bss
buffer:     .skip   16                   ; 16 byte buffer
temp_var:   .skip   2                    ; 2 byte temp variable

END
---------------------------------
