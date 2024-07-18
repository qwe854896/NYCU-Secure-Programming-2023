_start:
    ; Load values from memory
    mov eax, dword [rsp + 0x0]
    mov ebx, dword [rsp + 0x4]
    mov ecx, dword [rsp + 0x8]
    mov edx, dword [rsp + 0xc]

    ; Compare a and b
    cmp eax, ebx
    jge a_greater_than_or_equal_to_b
    mov eax, ebx
    jmp a_greater_than_or_equal_to_b

a_greater_than_or_equal_to_b:
    ; Compare c and d
    cmp ecx, edx
    jb c_less_than_d
    mov ebx, edx
    jmp check_c_odd

c_less_than_d:
    mov ebx, ecx
    jmp check_c_odd

check_c_odd:
    ; Check if c is odd
    test ecx, 1
    jnz c_is_odd
    shl ecx, 2
    jmp end

c_is_odd:
    shr ecx, 3
    jmp end

end:
