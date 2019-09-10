; https://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1
; https://www.officedaytime.com/tips/simd.html

bits 64			; 64bit コードの指定
default rel		; デフォルトで RIP相対アドレシングを利用する

global sha1_update_intel

%assign multiblock 1

%xdefine ctx rdi
%xdefine buf rsi
; %xdefine cnt rdx

%xdefine A ecx
%xdefine B esi
%xdefine C edi
%xdefine D ebp
%xdefine E edx
%xdefine T1 eax
%xdefine T2 ebx

%xdefine HASH_PTR   r9
%xdefine BUFFER_PTR r10
; %xdefine BUFFER_END r11

%xdefine W_TMP  xmm0
%xdefine XMM_SHUFB_BSWAP xmm9
%xdefine W_TMP2 xmm15
; %xdefine K_VAL	xmm11

; we keep window of 64 w[i]+K pre-calculated values in a circular buffer
%xdefine WK(t) (rsp + (t & 15)*4)


; -----------------------------------------
%macro W_PRECALC_RESET  0
	%xdefine    W             xmm1
	%xdefine    W_minus_04    xmm2
	%xdefine    W_minus_08    xmm3
	%xdefine    W_minus_12    xmm4
	%xdefine    W_minus_16    xmm5
	%xdefine    W_minus_20    xmm6
	%xdefine    W_minus_24    xmm7
	%xdefine    W_minus_28    xmm8
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
	%xdefine    W             W_minus_32	; W_minus_32 = W_minus_28
%endmacro


; -----------------------------------------
%macro  DEPO_W_INIT  0
	%assign  cnt_DEPO_W  1
	%assign  Yn  10
%endmacro

%define  XMM_(n)  xmm %+ n
%define  YMM_(n)  ymm %+ n

%macro  DEPO_W  1		; 引数は、退避させたい xmm レジスタ
	%if (cnt_DEPO_W <= 12)
		%if ((cnt_DEPO_W & 1) == 1)		; cnt_DEPO_W は 12 以下
			movdqa		XMM_(Yn), %1
		%else
			vperm2i128	YMM_(Yn), YMM_(Yn), YMM_(Yn), 1
			movdqa		XMM_(Yn), %1
			vperm2i128	YMM_(Yn), YMM_(Yn), YMM_(Yn), 1
			%assign  Yn  Yn + 1
		%endif
		%assign  cnt_DEPO_W  cnt_DEPO_W + 1
	%endif
%endmacro


; -----------------------------------------
%macro W_PRECALC_00_15  2
	movdqu	W_TMP, [BUFFER_PTR + %2]	; W_TMP = xmm0, BUFFER_PTR = r10
	pshufb	W_TMP, XMM_SHUFB_BSWAP		; XMM_SHUFB_BSWAP = xmm10
	movdqa	W, W_TMP					; xmm1 -> xmm8 -> xmm7 -> xmm6 の順に値が設定される
;	paddd	W_TMP, K_VAL
	movdqa	[WK(%1)], W_TMP				; 最初の呼び出しでは WK(0), WK(4), WK(8), W(12) のいずれかになる

	DEPO_W	W  							; W の値退避させる
	W_PRECALC_ROTATE
%endmacro


%macro W_PRECALC_16_31  1
	movdqa  W, W_minus_12		; W = W_minus_12 = W7 W6 W5 W4
	palignr W, W_minus_16, 8	; W_minus_16 = W3 W2 W1 W0 -> W = W5 W4 W3 W2
	pxor    W, W_minus_08		; W_minus_08 = W11 W10 W9 W8 -> W = (W11 W10 W9 W8) ^ (W5 W4 W3 W2)

	movdqa  W_TMP, W_minus_04	; W_TMP = W_minus_04 = W15 W14 W13 W12
	psrldq  W_TMP, 4			; W_TMP = 0 W15 W14 W13
	pxor    W_TMP, W_minus_16	; W_TMP = (0 W15 W14 W13) ^ (W3 W2 W1 W0)
	pxor    W, W_TMP			; W = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)
	movdqa  W_TMP, W			; W_TMP = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)
	movdqa  W_TMP2, W			; W_TMP2 = (0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)

	pslld   W_TMP, 1
	psrld   W, 31
	por     W_TMP, W			; W_TMP = S^1((0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0))

	pslldq  W_TMP2, 12			; W_TMP2 = (W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0)
	movdqa  W, W_TMP2			; W = (W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0)
	pslld   W, 2
	psrld   W_TMP2, 30
	por		W, W_TMP2			; W = S^2((W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0))

	pxor	W, W_TMP			; W = S^2((W13 0 0 0) ^ (W8 0 0 0) ^ (W2 0 0 0) ^ (W0 0 0 0))
								;	^ (S^1((0 W15 W14 W13) ^ (W11 W10 W9 W8) ^ (W5 W4 W3 W2) ^ (W3 W2 W1 W0)))
								;   = (WW19 W18 W17 W16)
	movdqa	W_TMP, W
;	paddd   W_TMP, K_VAL
	movdqa  [WK(%1)], W_TMP

	DEPO_W	W
	W_PRECALC_ROTATE
%endmacro


%macro W_PRECALC_32_79  1
;; in SHA-1 specification: w[i] = (w[i-3] ^ w[i-8]  ^ w[i-14] ^ w[i-16]) rol 1
;; instead we do equal:    w[i] = (w[i-6] ^ w[i-16] ^ w[i-28] ^ w[i-32]) rol 2

	movdqa  W_TMP, W_minus_04		; W_TMP = W31 W30 W29 W28
	palignr W_TMP, W_minus_08, 8	; W_TMP = W29 W28 W27 W26

	pxor    W, W_minus_28			; W = (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	pxor    W, W_minus_16			; W = (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0)
	pxor    W, W_TMP				; W = (W29 W28 W27 W26) ^ (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0)

	movdqa  W_TMP, W
	psrld   W, 30
	pslld   W_TMP, 2
	por     W, W_TMP				; W_TMP = S^2((W29 W28 W27 W26) ^ (W19 W18 W17 W16) ^ (W7 W6 W5 W4) ^ (W3 W2 W1 W0))
									;       = W35 W34 W33 W32

	movdqa  W_TMP, W
;	paddd   W_TMP, K_VAL
	movdqa  [WK(%1)],W_TMP

	DEPO_W	W
	W_PRECALC_ROTATE
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

	F    %2, %3, %4     ;; F returns result in T1
	add  %5, [WK(%6)]
	rol  %2, 30
	mov  T2, %1
	add  %4, [WK(%6 + 1)]
	rol  T2, 5
	add  %5, T1

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

	align 32

bswap_shufb_ctl:
	DD 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f

; ========================================================
section .text align=4096

; 元は SHA1_VECTOR_ASM マクロであった部分
	align 4096

sha1_update_intel:   ;; ----- コード開始位置
	push	rbx
	push	rbp

	push	r12
	push	r13
	push	r14
	push	r15

;;; ==================
;;; テストコード
	mov		r15, rdx	; 第３引数（W_asm）
;;; ==================

	%xdefine stack_size (16*4 + 8)  ; 72bytes
	sub     rsp, stack_size

	mov     HASH_PTR, ctx		; 第１引数（state）
	mov     BUFFER_PTR, buf		; 第２引数（data）

	movdqa  XMM_SHUFB_BSWAP, [bswap_shufb_ctl]

	mov		A, [HASH_PTR   ]
	mov		B, [HASH_PTR+ 4]
	mov		C, [HASH_PTR+ 8]
	mov		D, [HASH_PTR+12]
	mov		E, [HASH_PTR+16]

;--------------------------------------------
; 処理開始

	DEPO_W_INIT
	W_PRECALC_RESET

;	vmovdqa		K_VAL, [K_XMM_AR]
	W_PRECALC_00_15	 0, 0  ; %1 <- %2
	W_PRECALC_00_15	 4, 16
	W_PRECALC_00_15	 8, 32
	W_PRECALC_00_15	 12, 48

	W_PRECALC_16_31  0
	W_PRECALC_16_31  4
	W_PRECALC_16_31  8
	W_PRECALC_16_31  12

	W_PRECALC_32_79  0
	W_PRECALC_32_79  4
	W_PRECALC_32_79  8
	W_PRECALC_32_79  12

	W_PRECALC_32_79  0
	W_PRECALC_32_79  4
	W_PRECALC_32_79  8
	W_PRECALC_32_79  12

	W_PRECALC_32_79  0
	W_PRECALC_32_79  4
	W_PRECALC_32_79  8
	W_PRECALC_32_79  12


	; F1 は、T1 = (%1 and %2) or (not(%1) and %3) を計算する
	%xdefine F F1


;;; ==================
;;; DEPO_W のテスト
	vmovdqa		[r15], ymm10
	add			r15, 32
	vmovdqa		[r15], ymm11
	add			r15, 32
	vmovdqa		[r15], ymm12
	add			r15, 32
	vmovdqa		[r15], ymm13
	add			r15, 32
	vmovdqa		[r15], ymm14
	add			r15, 32
	vmovdqa		[r15], ymm15
	add			r15, 32
	movdqa		[r15], W_minus_32
	add			r15, 16
	movdqa		[r15], W_minus_28
	add			r15, 16
	movdqa		[r15], W_minus_24
	add			r15, 16
	movdqa		[r15], W_minus_20
	add			r15, 16
	movdqa		[r15], W_minus_16
	add			r15, 16
	movdqa		[r15], W_minus_12
	add			r15, 16
	movdqa		[r15], W_minus_08
	add			r15, 16
	movdqa		[r15], W_minus_04
;;; ==================

	add		rsp, stack_size
	pop		r15
	pop		r14
	pop		r13
	pop		r12

	pop		rbp
	pop		rbx
	ret

