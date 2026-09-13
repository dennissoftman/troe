.intel_syntax noprefix
.text
.global _start
_start:
1:
    inc qword ptr fs:[16]
    mov rax, qword ptr fs:[8]
    inc qword ptr [rax]
    cmp qword ptr [rax + 8], 0
    jne 1b
    mov eax, 1
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    int 0x80
    jmp 1b
