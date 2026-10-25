.syntax unified
.cpu arm926ej-s
.arm
.global _start
_start:
    @ Offline Unicorn marker only; NOT invoked by current overflow.
    @ r0 must point to an isolated writable scratch buffer.
    adr r1, marker_text
    mov r2, #marker_text_end - marker_text
copy_loop:
    ldrb r3, [r1], #1
    strb r3, [r0], #1
    subs r2, r2, #1
    bne copy_loop
    bx lr
marker_text:
    .ascii "Hello, LG World!\nU H4VE 8EEN PWND BR0! <3"
marker_text_end:
