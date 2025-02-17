Example program
===============

```
; Immediate operands and address operands can specify an integer constant
; or a label name.
abp temp_area         ; Immediate operand
inp [max_steps]       ; Address operand (absolute)
add 0, 0, [counter]

; Labels can be on anything, instructions and operands.
; If they're on a line by themselves, they refer to the next instruction.
normal_loop:
cmplt [counter], [max_steps], [bp+0]   ; 3rd operand is a relative address operand (offset 0)
jz [bp + 0], self_modifying_loop
out [counter]
add 1, [counter], [counter]
jnz 1, normal_loop

self_modifying_loop:
cmplt self_modifying_counter:0, [max_steps], [bp+1]        ; Label on the first operand
jz [bp + 1], exit
out [self_modifying_counter]
add 1, [self_modifying_counter], [self_modifying_counter]  ; Directly modify the immediate operand
                                                           ; of the cmplt instruction
jnz 1, self_modifying_loop

exit: halt    ; Label in front of an instruction mnemonic is the same as a label on an
              ; empty line preceding the instruction.

; Data definition. The DI pseudo instruction does not emit any opcode, only its operand.
; And it can only take an immediate operand (for obvious reasons).
; This creates 3 integers in the output, each with the value zero.
; Including the halt instruction above, the intcode output ends in 99,0,0,0
; Each of these is also labeled, so the code above can address them.
di max_steps:0
di counter:0
di temp_area:0


; Instruction mnemonics are case-insensitive.
; In order of opcode value (starting from 1), they are:
; ADD, MUL, INP, OUT, JNZ, JZ, CMPLT, CMPEQ, ABP
```

