; https://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1

global sha1_update_intel
%assign multiblock 1

bits 64  ; 64bit コードの指定
default rel  ; デフォルトで RIP相対アドレシングを利用する

%xdefine ctx rdi
%xdefine buf rsi
%xdefine cnt rdx

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


;------------------------------------------------------------------------------
; SHA-1 function's body for single or several 64-byte blocks
;
; first param: function's name
;
; second param: =0 - function implements single 64-byte block hash
;               =1 - function implements multiple64-byte blocks hash

%macro  SHA1_VECTOR_ASM  2
	align 4096

%1:
	push rbx
	push rbp

	%xdefine stack_size (16*4 + 8)
	sub     rsp, stack_size

	mov     HASH_PTR, ctx
	mov     BUFFER_PTR, buf

	%if (%2 == 1)
		shl     cnt, 6         ;; mul by 64
		add     cnt, buf       ;; cnt の内容が破壊される
		mov     BUFFER_END, cnt
	%endif

	lea     K_BASE, [K_XMM_AR]
	movdqa  XMM_SHUFB_BSWAP, [bswap_shufb_ctl]

	SHA1_PIPELINED_MAIN_BODY %2

	add rsp, stack_size
	pop rbp
	pop rbx
	ret
%endmacro


;;----------------------
section .data align=128

	%xdefine K1 0x5a827999
	%xdefine K2 0x6ed9eba1
	%xdefine K3 0x8f1bbcdc
	%xdefine K4 0xca62c1d6

	align 128

K_XMM_AR:
	DD K1, K1, K1, K1
	DD K2, K2, K2, K2
	DD K3, K3, K3, K3
	DD K4, K4, K4, K4

	align 16

bswap_shufb_ctl:
	DD 00010203h
	DD 04050607h
	DD 08090a0bh
	DD 0c0d0e0fh


;;----------------------

section .text align=4096
	SHA1_VECTOR_ASM     sha1_update_intel_ssse3_, multiblock

	align 32

sha1_update_intel_init_:       ;; we get here with the first time invocation
	call    sha1_update_intel_dispacth_init_

sha1_update_intel:    ;; we get here after init

	jmp     qword [sha1_update_intel_dispatched]

	;; CPUID feature flag based dispatch

sha1_update_intel_dispacth_init_:
	push    rax
	push    rbx
	push    rcx
	push    rdx
	push    rsi

	lea     rsi, [INTEL_SHA1_UPDATE_DEFAULT_DISPATCH]
	mov     eax, 1

	cpuid
	test    ecx, 0200h          ;; SSSE3 support, CPUID.1.ECX[bit 9]
	jz      _done
	lea     rsi, [sha1_update_intel_ssse3_]

_done:
	mov     [sha1_update_intel_dispatched], rsi
	pop     rsi
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
	ret

	;;----------------------
	;; in the case a default SHA-1 update function implementation was not provided
	;; and code was invoked on a non-SSSE3 supporting CPU, dispatch handles this
	;; failure in a safest way - jumps to the stub function with UD2 instruction below

sha1_intel_non_ssse3_cpu_stub_:

	ud2     ;; in the case no default SHA-1 was provided non-SSSE3 CPUs safely fail here
	ret

	; END
	;----------------------
