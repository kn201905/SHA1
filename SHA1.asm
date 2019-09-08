; https://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1
; https://www.officedaytime.com/tips/simd.html

global sha1_update_intel
%assign multiblock 1

bits 64  ; 64bit コードの指定
default rel  ; デフォルトで RIP相対アドレシングを利用する

%xdefine ctx rdi
%xdefine buf rsi
%xdefine cnt rdx

%xdefine A ecx
%xdefine B esi
%xdefine C edi
%xdefine D ebp
%xdefine E edx
%xdefine T1 eax
%xdefine T2 ebx

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

; we keep window of 64 w[i]+K pre-calculated values in a circular buffer
%xdefine WK(t) (rsp + (t & 15)*4)


%macro W_PRECALC_RESET 0
	%xdefine    W             W0
	%xdefine    W_minus_04    W4
	%xdefine    W_minus_08    W8
	%xdefine    W_minus_12    W12
	%xdefine    W_minus_16    W16
	%xdefine    W_minus_20    W20
	%xdefine    W_minus_24    W24
	%xdefine    W_minus_28    W28
	%xdefine    W_minus_32    W
%endmacro


%macro W_PRECALC_ROTATE 0
	%xdefine    W_minus_32    W_minus_28
	%xdefine    W_minus_28    W_minus_24
	%xdefine    W_minus_24    W_minus_20
	%xdefine    W_minus_20    W_minus_16
	%xdefine    W_minus_16    W_minus_12
	%xdefine    W_minus_12    W_minus_08
	%xdefine    W_minus_08    W_minus_04
	%xdefine    W_minus_04    W
	%xdefine    W             W_minus_32
%endmacro


%xdefine W_PRECALC_AHEAD   16
%xdefine W_NO_TAIL_PRECALC 0


%macro W_PRECALC_00_15 0   ;; message scheduling pre-compute for rounds 0-15
	%if ((i & 3) == 0)       ;; blended SSE and ALU instruction scheduling, 1 vector iteration per 4 rounds
		movdqu	W_TMP, [BUFFER_PTR + (i * 4)]  ; BUFFER_PTR = r10

	%elif ((i & 3) == 1)
		pshufb	W_TMP, XMM_SHUFB_BSWAP  ; W_TMP = xmm0
		movdqa	W, W_TMP

	%elif ((i & 3) == 2)
		paddd	W_TMP, [K_BASE]  ; K_BASE = r8 = K_XMM_AR, paddd = Packed ADD 32bits

	%elif ((i & 3) == 3)
		movdqa	[WK(i&~3)], W_TMP  ; WK(0), WK(4), WK(8), W(12) のいずれかになる
		W_PRECALC_ROTATE
	%endif
%endmacro


%macro W_PRECALC 1
	%xdefine i (%1)

	%if (i < 20)
		%xdefine K_XMM  0
	%elif (i < 40)
		%xdefine K_XMM  16
	%elif (i < 60)
		%xdefine K_XMM  32
	%else
		%xdefine K_XMM  48
	%endif

	%if (i < 16 || (i >= 80 && i < (80 + W_PRECALC_AHEAD)))
		%if (W_NO_TAIL_PRECALC == 0)
			%xdefine i ((%1) % 80)        ;; pre-compute for the next iteration
			%if (i == 0)
				W_PRECALC_RESET
			%endif

			W_PRECALC_00_15
		%endif

	%elif (i < 32)
;;; =============================
;;; テスト中
;;;		W_PRECALC_16_31

	%elif (i < 80)   ;; rounds 32-79
;;; =============================
;;; テスト中
;;;		W_PRECALC_32_79
	%endif
%endmacro


%macro F1 3
	mov T1,%2  ; T1 = eax
	xor T1,%3
	and T1,%1
	xor T1,%3
%endmacro


; ----------------------
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


; --------------------------------------------
section .text align=4096

; 元は SHA1_VECTOR_ASM マクロであった部分
	align 4096

sha1_update_intel:   ;; コード開始位置
	push	rbx
	push	rbp

;;; ==================
;;; テストコード
	movq	xmm15, rcx  ; 第４引数の退避

	%xdefine stack_size (16*4 + 8)  ; 72bytes
	sub     rsp, stack_size

	mov     HASH_PTR, ctx		; 第１引数
	mov     BUFFER_PTR, buf		;; 第２引数

	%if (multiblock == 1)
		shl     cnt, 6			;; mul by 64 , cnt は 第３引数
		add     cnt, buf		;; cnt の内容が破壊される
		mov     BUFFER_END, cnt	;; BUFFER_END = r11
	%endif

	lea     K_BASE, [K_XMM_AR]
	movdqa  XMM_SHUFB_BSWAP, [bswap_shufb_ctl]

;--------------------------------------------
; macro param: =0 - process single 64-byte block
;              =1 - multiple blocks
; %macro SHA1_PIPELINED_MAIN_BODY 1

	mov		A, [HASH_PTR   ]
	mov		B, [HASH_PTR+ 4]
	mov		C, [HASH_PTR+ 8]
	mov		D, [HASH_PTR+12]
	mov		E, [HASH_PTR+16]

	%assign i 0
	%rep    W_PRECALC_AHEAD	; = 16
		W_PRECALC i			; 0 <= i <= 15
		%assign i i+1
	%endrep

	%xdefine F F1

	%if (multiblock == 1)               ; code loops through more than one block
pp_loop:
		cmp BUFFER_PTR, K_BASE          ; we use K_BASE value as a signal of a last block,
		jne pp_begin                    ; it is set below by: cmovae BUFFER_PTR, K_BASE
		jmp pp_end			; <<SHA1_PIPELINED_MAIN_BODY_END>> へジャンプする

		align 32
pp_begin:
	%endif


;;; SHA1_PIPELINED_MAIN_BODY の終了付近のコード
pp_end:		; <<SHA1_PIPELINED_MAIN_BODY_END>>
;;;	%endif

;;;	%xdefine W_NO_TAIL_PRECALC 0
;;;	%xdefine F %error
; %endmacro		; SHA1_PIPELINED_MAIN_BODY の終了


;;; ==================
;;; テストコード
	movq	rcx, xmm15  ; 第４引数の復帰
	vmovdqu	ymm0, [rsp]  ; 32bytes コピー
	vmovdqa [rcx], ymm0
	vmovdqu	ymm0, [rsp + 32]  ; 32bytes コピー
	vmovdqa [rcx + 32], ymm0
	mov		rax, [rsp + 64]  ; 8bytes コピー
	mov		[rcx + 64], rax
;;; ==================

	add		rsp, stack_size
	pop		rbp
	pop		rbx
	ret

