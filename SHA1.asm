section .text
global sha1_update_intel
%assign multiblock 1

bits 64  ; 64bit コードの指定
default rel  ; デフォルトで RIP相対アドレシングを利用する

%xdefine arg1 rdi
%xdefine arg2 rsi
%xdefine arg3 rdx

%xdefine ctx arg1
%xdefine buf arg2
%xdefine cnt arg3

%macro REGALLOC 0
%xdefine A ecx
%xdefine B esi
%xdefine C edi
%xdefine D ebp
%xdefine E edx
%xdefine T1 eax
%xdefine T2 ebx
%endmacro

%xdefine K_BASE     r8
%xdefine HASH_PTR   r9
%xdefine BUFFER_PTR r10
%xdefine BUFFER_END r11

%xdefine W_TMP  xmm0
%xdefine W_TMP2 xmm9

%xdefine W0  xmm1
%xdefine W4  xmm2
%xdefine W8  xmm3
%xdefine W12 xmm4
%xdefine W16 xmm5
%xdefine W20 xmm6
%xdefine W24 xmm7
%xdefine W28 xmm8

%xdefine XMM_SHUFB_BSWAP xmm10

;; we keep window of 64 w[i]+K pre-calculated values in a circular buffer
%xdefine WK(t) (rsp + (t & 15)*4)

sha1_update_intel:
    enter 0,0
    mov eax, edi
    mov ebx, esi
    add eax, ebx
    leave
    ret
