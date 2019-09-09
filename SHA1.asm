; https://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1
; https://www.officedaytime.com/tips/simd.html

bits 64  ; 64bit コードの指定
default rel  ; デフォルトで RIP相対アドレシングを利用する

global sha1_update_intel

%assign multiblock 1

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
	%xdefine    W             W0	; W0 = xmm1
	%xdefine    W_minus_04    W4	; W4 = xmm2
	%xdefine    W_minus_08    W8	; W8 = xmm3
	%xdefine    W_minus_12    W12	; W12 = xmm4
	%xdefine    W_minus_16    W16	; W16 = xmm5
	%xdefine    W_minus_20    W20	; W20 = xmm6
	%xdefine    W_minus_24    W24	; W24 = xmm7
	%xdefine    W_minus_28    W28	; W28 = xmm8
	%xdefine    W_minus_32    W		; W = W0 = xmm1
%endmacro


; W が xmm1 -> xmm8 -> xmm7 -> xmm6 -> xmm5 とローテーションする
; W_minus_04 が xmm2 -> xmm1 -> xmm8 -> xmm7 -> xmm6
; W_minus_08 が xmm3 -> xmm2 -> xmm1 -> xmm8 -> xmm7
; W_minus_12 が xmm4 -> xmm3 -> xmm2 -> xmm1 -> xmm8
; W_minus_16 が xmm5 -> xmm4 -> xmm3 -> xmm2 -> xmm1
%macro W_PRECALC_ROTATE 0
	%xdefine    W_minus_32    W_minus_28
	%xdefine    W_minus_28    W_minus_24
	%xdefine    W_minus_24    W_minus_20
	%xdefine    W_minus_20    W_minus_16
	%xdefine    W_minus_16    W_minus_12
	%xdefine    W_minus_12    W_minus_08
	%xdefine    W_minus_08    W_minus_04
	%xdefine    W_minus_04    W
	%xdefine    W             W_minus_32	; W_minus_32 = W_minus_28
%endmacro


%xdefine W_PRECALC_AHEAD   16
%xdefine W_NO_TAIL_PRECALC 0


%macro W_PRECALC_00_15  2
	movdqu	W_TMP, [BUFFER_PTR + %2]	; W_TMP = xmm0, BUFFER_PTR = r10
	pshufb	W_TMP, XMM_SHUFB_BSWAP		; XMM_SHUFB_BSWAP = xmm10
	movdqa	W, W_TMP					; xmm1 -> xmm8 -> xmm7 -> xmm6 の順に値が設定される
	paddd	W_TMP, [K_BASE]				; K_BASE = r8（= K_XMM_AR）, paddd = Packed ADD 32bits
	movdqa	[WK(%1)], W_TMP				; 最初の呼び出しでは WK(0), WK(4), WK(8), W(12) のいずれかになる

	W_PRECALC_ROTATE
%endmacro


%macro W_PRECALC_16_31  2
	movdqa  W, W_minus_12		; W = W_minus_12 = W7 W6 W5 W4
	palignr W, W_minus_16, 8	; W_minus_16 = W3 W2 W1 W0 -> W = W5 W4 W3 W2
	pxor    W, W_minus_08		; W_minus_08 = W11 W10 W9 W8 -> W = (W11 W10 W9 W8) ^ (W5 W4 W3 W2)

	movdqa  W_TMP, W_minus_04	; W_TMP = W_minus_04 = W15 W14 W13 W12
	psrldq  W_TMP, 4			; W_TMP = 0 W15 W14 W13
	pxor    W_TMP, W_minus_16	; W_TMP = (0 W15 W14 W13) ^ (W3 W2 W1 W0)
	pxor    W, W_TMP			; W = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)

	movdqa  W_TMP2, W			; W_TMP2 = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)
	pslldq  W_TMP2, 12			; W_TMP2 = (W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0)

	movdqa  W_TMP, W			; W_TMP = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)
	pslld   W_TMP, 1
	psrld   W, 31
	por     W_TMP, W			; W_TMP = S^1((0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0))

	movdqa  W, W_TMP2			; W = (W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0)
	pslld   W, 2
	psrld   W_TMP2, 30
	por		W, W_TMP2			; W = S^2((W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0))

	pxor	W, W_TMP			; W = S^2((W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0))
								;	^ (S^1((0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)))
								;   = (WW19 W18 W17 W16)
	movdqa	W_TMP, W
	paddd   W_TMP, [K_BASE + %2]
	movdqa  [WK(%1)], W_TMP

	W_PRECALC_ROTATE
%endmacro


%macro W_PRECALC_32_79  2
;; in SHA-1 specification: w[i] = (w[i-3] ^ w[i-8]  ^ w[i-14] ^ w[i-16]) rol 1
;; instead we do equal:    w[i] = (w[i-6] ^ w[i-16] ^ w[i-28] ^ w[i-32]) rol 2

	movdqa  W_TMP, W_minus_04		; W_TMP = W31 W30 W29 W28
	pxor    W, W_minus_28			; W = (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	palignr W_TMP, W_minus_08, 8	; W_TMP = W29 W28 W27 W26

	pxor    W, W_minus_16			; W = (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	pxor    W, W_TMP				; W = (W29 W28 W27 W26) ^ (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	movdqa  W_TMP, W

	psrld   W, 30
	pslld   W_TMP, 2
	por     W_TMP, W				; W_TMP = S^2((W29 W28 W27 W26) ^ (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0))
									;       = W35 W34 W33 W32

	movdqa  W, W_TMP
	paddd   W_TMP, [K_BASE + %2]
	movdqa  [WK(%1)],W_TMP

	W_PRECALC_ROTATE
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

	%if (i < 16 || (i >= 80 && i < (80 + W_PRECALC_AHEAD)))	;; i = 0,...,15 , 80,...,95
		%if (W_NO_TAIL_PRECALC == 0)
			%xdefine i ((%1) % 80)        ;; pre-compute for the next iteration
			%if (i == 0)
				W_PRECALC_RESET
			%endif

			W_PRECALC_00_15
		%endif

	%elif (i < 32)
		W_PRECALC_16_31

	%elif (i < 80)   ;; rounds 32-79
;;; =============================
;;; テスト中
;;;		W_PRECALC_32_79
	%endif
%endmacro


; 以下は、T1 = (%1 and %2) or (not(%1) and %3) と等価
%macro F1 3
	mov T1,%2  ; T1 = eax
	xor T1,%3  ; T1 = %2 xor %3
	and T1,%1
	xor T1,%3
%endmacro


%macro RR 6		;; RR does two rounds of SHA-1 back to back with W pre-calculation
; %1 = C_2,  %2 = D_2,  %3 = E_2,  %4 = A_2,  %5 = B_2

	W_PRECALC (%6 + W_PRECALC_AHEAD)	; W_PRECALC_AHEAD は常に 16
	F    %2, %3, %4     ;; F returns result in T1
	add  %5, [WK(%6)]
	rol  %2, 30
	mov  T2, %1
	add  %4, [WK(%6 + 1)]
	rol  T2, 5
	add  %5, T1

	W_PRECALC (%6 + W_PRECALC_AHEAD + 1)
	add  T2, %5
	mov  %5, T2
	rol  T2, 5
	add  %4, T2

	F    %1, %2, %3    ;; F returns result in T1
	add  %4, T1
	rol  %1, 30
%endmacro


; ========================================================
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

ORD_VRFY_VAL_128:
	DQ 0x090a0b0c0d0e0f10, 0x0102030405060708

; ========================================================
section .text align=4096

; 元は SHA1_VECTOR_ASM マクロであった部分
	align 4096

sha1_update_intel:   ;; ----- コード開始位置
	push	rbx
	push	rbp

;;; ==================
;;; テストコード
	movq	xmm15, rcx  ; 第４引数の退避
	mov		r15, r8	; 第５引数の退避
;;; ==================

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

	mov		A, [HASH_PTR   ]
	mov		B, [HASH_PTR+ 4]
	mov		C, [HASH_PTR+ 8]
	mov		D, [HASH_PTR+12]
	mov		E, [HASH_PTR+16]

;--------------------------------------------
; 処理開始

	; スタック領域（64bytes）に初期値を設定する
	W_PRECALC_RESET
	W_PRECALC_00_15	 0, 0  ; %1 <- %2
	W_PRECALC_00_15	 4, 16
	W_PRECALC_00_15	 8, 32
	W_PRECALC_00_15	 12, 48

	; F1 は、T1 = (%1 and %2) or (not(%1) and %3) を計算する
	%xdefine F F1

	W_PRECALC_16_31  0, 0  ; %1 <- %2
	W_PRECALC_16_31  4, 16
	W_PRECALC_16_31  8, 16
	W_PRECALC_16_31  12, 16

	W_PRECALC_32_79  0, 16
	W_PRECALC_32_79  4, 16
	W_PRECALC_32_79  8, 32
	W_PRECALC_32_79  12, 32

	W_PRECALC_32_79  0, 32
	W_PRECALC_32_79  4, 32
	W_PRECALC_32_79  8, 32
	W_PRECALC_32_79  12, 48

	W_PRECALC_32_79  0, 48
	W_PRECALC_32_79  4, 48
	W_PRECALC_32_79  8, 48
	W_PRECALC_32_79  12, 48


;;; ==================
;;; スタックのコピー
	movq	rcx, xmm15			; 第４引数の復帰
	vmovdqu	ymm0, [rsp]
	vmovdqa [rcx], ymm0			; 32bytes コピー
	vmovdqu	ymm0, [rsp + 32]
	vmovdqa [rcx + 32], ymm0	; 32bytes コピー
	mov		rax, [rsp + 64]
	mov		[rcx + 64], rax		; 8bytes コピー
;;; ==================

	add		rsp, stack_size
	pop		rbp
	pop		rbx
	ret

