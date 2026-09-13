.text
.global _start
_start:
    mrs x19, tpidr_el0
1:
    ldr x0, [x19, #16]
    add x0, x0, #1
    str x0, [x19, #16]
    ldr x1, [x19, #8]
    ldr x0, [x1]
    add x0, x0, #1
    str x0, [x1]
    ldr x0, [x1, #8]
    cbnz x0, 1b
    mov x8, #1
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x5, #0
    svc #0
    b 1b
