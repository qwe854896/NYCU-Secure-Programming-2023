; Modify register value
add rax, 0x87
sub rbx, 0x63
xchg rcx, rdx

; Save register values to memory
push rax
push rdx

; ignore stack pointer
add rsp, 0x10

; Modify memory value
add dword [rsp + 0x0], 0xdeadbeef
sub dword [rsp + 0x4], 0xfaceb00c
mov eax, dword [rsp + 0x8]
mov edx, dword [rsp + 0xc]
mov dword [rsp + 0xc], eax
mov dword [rsp + 0x8], edx

; Bring rsp back
sub rsp, 0x10

; Restore register values from memory
pop rdx
pop rax
