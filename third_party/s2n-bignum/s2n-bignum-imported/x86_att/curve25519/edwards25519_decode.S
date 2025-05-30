// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Decode compressed 256-bit form of edwards25519 point
// Input c[32] (bytes); output function return and z[8]
//
// extern uint64_t edwards25519_decode(uint64_t z[static 8], const uint8_t c[static 32]);
//
// This interprets the input byte string as a little-endian number
// representing a point (x,y) on the edwards25519 curve, encoded as
// 2^255 * x_0 + y where x_0 is the least significant bit of x. It
// returns the full pair of coordinates x (at z) and y (at z+4). The
// return code is 0 for success and 1 for failure, which means that
// the input does not correspond to the encoding of any edwards25519
// point. This can happen for three reasons, where y = the lowest
// 255 bits of the input:
//
//  * y >= p_25519
//    Input y coordinate is not reduced
//  * (y^2 - 1) * (1 + d_25519 * y^2) has no modular square root
//    There is no x such that (x,y) is on the curve
//  * y^2 = 1 and top bit of input is set
//    Cannot be the canonical encoding of (0,1) or (0,-1)
//
// Standard x86-64 ABI: RDI = z, RSI = c
// Microsoft x64 ABI:   RCX = z, RDX = c
// ----------------------------------------------------------------------------
#include "_internal_s2n_bignum.h"


        S2N_BN_SYM_VISIBILITY_DIRECTIVE(edwards25519_decode)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(edwards25519_decode)
        .text

// Size in bytes of a 64-bit word

#define N 8

// Pointer-offset pairs for temporaries on stack

#define y 0(%rsp)
#define s (4*N)(%rsp)
#define t (8*N)(%rsp)
#define u (12*N)(%rsp)
#define v (16*N)(%rsp)
#define w (20*N)(%rsp)
#define q (24*N)(%rsp)
#define res  (28*N)(%rsp)
#define sgnbit  (29*N)(%rsp)
#define badun  (30*N)(%rsp)

// Total size to reserve on the stack

#define NSPACE (32*N)

// Corrupted versions when stack is down 8 more

#define q8 (25*N)(%rsp)

// Syntactic variants to make x86_att version simpler to generate

#define Y 0
#define S (4*N)
#define T (8*N)
#define U (12*N)
#define V (16*N)
#define W (20*N)
#define Q8 (25*N)

S2N_BN_SYMBOL(edwards25519_decode):
        _CET_ENDBR

// In this case the Windows form literally makes a subroutine call.
// This avoids hassle arising from subroutine offsets

#if WINDOWS_ABI
        pushq   %rdi
        pushq   %rsi
        movq    %rcx, %rdi
        movq    %rdx, %rsi
        callq   edwards25519_decode_standard
        popq    %rsi
        popq    %rdi
        ret

edwards25519_decode_standard:
#endif

// Save registers and make room for temporaries

        pushq   %rbx
        pushq   %rbp
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15

        subq    $NSPACE, %rsp

// Save the return pointer for the end so we can overwrite %rdi later

        movq    %rdi, res

// Load the inputs, which can be done word-wise since x86 is little-endian.
// Let y be the lowest 255 bits of the input and sgnbit the desired parity.
// If y >= p_25519 then already flag the input as invalid (badun = 1).

        movq    (%rsi), %rax
        movq    %rax, Y(%rsp)
        movq    8(%rsi), %rbx
        movq    %rbx, Y+8(%rsp)
        xorl    %ebp, %ebp
        movq    16(%rsi), %rcx
        movq    %rcx, Y+16(%rsp)
        movq    24(%rsi), %rdx
        btr     $63, %rdx
        movq    %rdx, Y+24(%rsp)
        adcq    %rbp, %rbp
        movq    %rbp, sgnbit

        addq    $19, %rax
        adcq    $0, %rbx
        adcq    $0, %rcx
        adcq    $0, %rdx
        shrq    $63, %rdx
        movq    %rdx, badun

// u = y^2 - 1 (actually y + 2^255-20, not reduced modulo)
// v = 1 + d * y^2 (not reduced modulo from the +1)
// w = u * v

        leaq    V(%rsp), %rdi
        movq    $1, %rsi
        leaq    Y(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519
        movq    V(%rsp), %rax
        subq    $20, %rax
        movq    V+8(%rsp), %rbx
        sbbq    $0, %rbx
        movq    V+16(%rsp), %rcx
        sbbq    $0, %rcx
        movq    V+24(%rsp), %rdx
        sbbq    $0, %rdx
        btc     $63, %rdx
        movq    %rax, U(%rsp)
        movq    %rbx, U+8(%rsp)
        movq    %rcx, U+16(%rsp)
        movq    %rdx, U+24(%rsp)

        movq    $0x75eb4dca135978a3, %rax
        movq    %rax, W(%rsp)
        movq    $0x00700a4d4141d8ab, %rax
        movq    %rax, W+8(%rsp)
        movq    $0x8cc740797779e898, %rax
        movq    %rax, W+16(%rsp)
        movq    $0x52036cee2b6ffe73, %rax
        movq    %rax, W+24(%rsp)
        leaq    V(%rsp), %rdi
        leaq    W(%rsp), %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519
        movq    V(%rsp), %rax
        addq    $1, %rax
        movq    V+8(%rsp), %rbx
        adcq    $0, %rbx
        movq    V+16(%rsp), %rcx
        adcq    $0, %rcx
        movq    V+24(%rsp), %rdx
        adcq    $0, %rdx
        movq    %rax, V(%rsp)
        movq    %rbx, V+8(%rsp)
        movq    %rcx, V+16(%rsp)
        movq    %rdx, V+24(%rsp)

        leaq    W(%rsp), %rdi
        leaq    U(%rsp), %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

// Get s = w^{252-3} as a candidate inverse square root 1/sqrt(w).
// This power tower computation is the same as bignum_invsqrt_p25519

        leaq    T(%rsp), %rdi
        movq    $1, %rsi
        leaq    W(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    T(%rsp), %rdi
        leaq    T(%rsp), %rsi
        leaq    W(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $2, %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    T(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $1, %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    V(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    W(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $5, %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    T(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $10, %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    T(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $5, %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    V(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $25, %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    T(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $50, %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    T(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $25, %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    V(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $125, %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    V(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

        leaq    S(%rsp), %rdi
        movq    $2, %rsi
        leaq    V(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    S(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    W(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

// Compute v' = s^2 * w to discriminate whether the square root sqrt(u/v)
// exists, in which case we should get 0, 1 or -1.

        leaq    V(%rsp), %rdi
        movq    $1, %rsi
        leaq    S(%rsp), %rdx
        callq   edwards25519_decode_nsqr_p25519

        leaq    V(%rsp), %rdi
        leaq    V(%rsp), %rsi
        leaq    W(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

// Get the two candidates for sqrt(u / v), one being s = u * w^{252-3}
// and the other being t = s * j_25519 where j_25519 = sqrt(-1).

        leaq    S(%rsp), %rdi
        leaq    U(%rsp), %rsi
        leaq    S(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519
        movq    $0xc4ee1b274a0ea0b0, %rax
        movq    %rax, T(%rsp)
        movq    $0x2f431806ad2fe478, %rax
        movq    %rax, T+8(%rsp)
        movq    $0x2b4d00993dfbd7a7, %rax
        movq    %rax, T+16(%rsp)
        movq    $0x2b8324804fc1df0b, %rax
        movq    %rax, T+24(%rsp)
        leaq    T(%rsp), %rdi
        leaq    S(%rsp), %rsi
        leaq    T(%rsp), %rdx
        callq   edwards25519_decode_mul_p25519

// %rax = 0 <=> s^2 * w = 0 or 1

        movq    V(%rsp), %r8
        movq    V+8(%rsp), %r9
        movq    V+16(%rsp), %r10
        movq    V+24(%rsp), %r11
        movl    $1, %eax
        notq    %rax
        andq    %r8, %rax
        orq     %r9, %rax
        orq     %r10, %rax
        orq     %r11, %rax

// %r8 = 0 <=> s^2 * w = -1 (mod p_25519, i.e. s^2 * w = 2^255 - 20)

        addq    $20, %r8
        notq    %r9
        notq    %r10
        bts     $63, %r11
        addq    $1, %r11
        orq     %r9, %r8
        orq     %r11, %r10
        orq     %r10, %r8

// If s^2 * w is not 0 or 1 then replace s by t

        testq   %rax, %rax

        movq    S(%rsp), %r12
        movq    T(%rsp), %rbx
        cmovnzq %rbx, %r12
        movq    S+8(%rsp), %r13
        movq    T+8(%rsp), %rbx
        cmovnzq %rbx, %r13
        movq    S+16(%rsp), %r14
        movq    T+16(%rsp), %rbx
        cmovnzq %rbx, %r14
        movq    S+24(%rsp), %r15
        movq    T+24(%rsp), %rbx
        cmovnzq %rbx, %r15
        movq    %r12, S(%rsp)
        movq    %r13, S+8(%rsp)
        movq    %r14, S+16(%rsp)
        movq    %r15, S+24(%rsp)

// Check invalidity, occurring if s^2 * w is not in {0,1,-1}

        cmovzq  %rax, %r8
        negq    %r8
        sbbq    %r8, %r8
        negq    %r8
        orq     %r8, badun

// Let [%r11;%r10;%r9;%r8] = s and [%r15;%r14;%r13;%r12] = p_25519 - s

        movq    S(%rsp), %r8
        movq    $-19, %r12
        subq    %r8, %r12
        movq    S+8(%rsp), %r9
        movq    $-1, %r13
        sbbq    %r9, %r13
        movq    S+16(%rsp), %r10
        movq    $-1, %r14
        sbbq    %r10, %r14
        movq    S+24(%rsp), %r11
        movq    $0x7FFFFFFFFFFFFFFF, %r15
        sbbq    %r11, %r15

// Decide whether a flip is apparently indicated, s_0 <=> sgnbit
// Decide also if s = 0 by OR-ing its digits. Now if a flip is indicated:
//  - if s = 0 then mark as invalid
//  - if s <> 0 then indeed flip

        movl    $1, %ecx
        andq    %r8, %rcx
        xorq    sgnbit, %rcx
        movq    badun, %rdx
        movq    %rdx, %rsi
        orq     %rcx, %rdx
        xorl    %ebp, %ebp
        movq    %r8, %rax
        movq    %r9, %rbx
        orq     %r10, %rax
        orq     %r11, %rbx
        orq     %rbx, %rax
        cmovzq  %rbp, %rcx
        cmovnzq %rsi, %rdx

// Actual selection of x as s or -s, copying of y and return of validity

        testq   %rcx, %rcx

        cmovnzq %r12, %r8
        cmovnzq %r13, %r9
        cmovnzq %r14, %r10
        cmovnzq %r15, %r11

        movq    res, %rdi
        movq    %r8, (%rdi)
        movq    %r9, 8(%rdi)
        movq    %r10, 16(%rdi)
        movq    %r11, 24(%rdi)
        movq    Y(%rsp), %rcx
        movq    %rcx, 32(%rdi)
        movq    Y+8(%rsp), %rcx
        movq    %rcx, 40(%rdi)
        movq    Y+16(%rsp), %rcx
        movq    %rcx, 48(%rdi)
        movq    Y+24(%rsp), %rcx
        movq    %rcx, 56(%rdi)

        movq    %rdx, %rax

// Restore stack and registers

        addq    $NSPACE, %rsp

        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %rbp
        popq    %rbx
        ret

// *************************************************************
// Local z = x * y
// *************************************************************

edwards25519_decode_mul_p25519:
        movq    %rdx, %rcx
        xorl    %ebp, %ebp
        movq    (%rcx), %rdx
        mulxq   (%rsi), %r8, %r9
        mulxq   0x8(%rsi), %rax, %r10
        addq    %rax, %r9
        mulxq   0x10(%rsi), %rax, %r11
        adcq    %rax, %r10
        mulxq   0x18(%rsi), %rax, %r12
        adcq    %rax, %r11
        adcq    %rbp, %r12
        xorl    %ebp, %ebp
        movq    0x8(%rcx), %rdx
        mulxq   (%rsi), %rax, %rbx
        adcxq   %rax, %r9
        adoxq   %rbx, %r10
        mulxq   0x8(%rsi), %rax, %rbx
        adcxq   %rax, %r10
        adoxq   %rbx, %r11
        mulxq   0x10(%rsi), %rax, %rbx
        adcxq   %rax, %r11
        adoxq   %rbx, %r12
        mulxq   0x18(%rsi), %rax, %r13
        adcxq   %rax, %r12
        adoxq   %rbp, %r13
        adcq    %rbp, %r13
        xorl    %ebp, %ebp
        movq    0x10(%rcx), %rdx
        mulxq   (%rsi), %rax, %rbx
        adcxq   %rax, %r10
        adoxq   %rbx, %r11
        mulxq   0x8(%rsi), %rax, %rbx
        adcxq   %rax, %r11
        adoxq   %rbx, %r12
        mulxq   0x10(%rsi), %rax, %rbx
        adcxq   %rax, %r12
        adoxq   %rbx, %r13
        mulxq   0x18(%rsi), %rax, %r14
        adcxq   %rax, %r13
        adoxq   %rbp, %r14
        adcq    %rbp, %r14
        xorl    %ebp, %ebp
        movq    0x18(%rcx), %rdx
        mulxq   (%rsi), %rax, %rbx
        adcxq   %rax, %r11
        adoxq   %rbx, %r12
        mulxq   0x18(%rsi), %rcx, %r15
        mulxq   0x8(%rsi), %rax, %rbx
        adcxq   %rax, %r12
        adoxq   %rbx, %r13
        mulxq   0x10(%rsi), %rax, %rbx
        adcxq   %rax, %r13
        adoxq   %rbx, %r14
        movl    $0x26, %edx
        mulxq   %r15, %rax, %rbx
        adcxq   %rcx, %r14
        adoxq   %rbp, %r15
        adcq    %rbp, %r15
        addq    %r11, %rax
        adcq    %rbp, %rbx
        btq     $0x3f, %rax
        adcq    %rbx, %rbx
        leaq    0x1(%rbx), %rcx
        imulq   $0x13, %rcx, %rcx
        xorl    %ebp, %ebp
        adoxq   %rcx, %r8
        mulxq   %r12, %rax, %rbx
        adcxq   %rax, %r8
        adoxq   %rbx, %r9
        mulxq   %r13, %rax, %rbx
        adcxq   %rax, %r9
        adoxq   %rbx, %r10
        mulxq   %r14, %rax, %rbx
        adcxq   %rax, %r10
        adoxq   %rbx, %r11
        mulxq   %r15, %rax, %rbx
        adcq    %rax, %r11
        shlq    $0x3f, %rcx
        cmpq    %rcx, %r11
        movl    $0x13, %eax
        cmovns  %rbp, %rax
        subq    %rax, %r8
        sbbq    %rbp, %r9
        sbbq    %rbp, %r10
        sbbq    %rbp, %r11
        btr     $0x3f, %r11
        movq    %r8, (%rdi)
        movq    %r9, 0x8(%rdi)
        movq    %r10, 0x10(%rdi)
        movq    %r11, 0x18(%rdi)
        ret

// *************************************************************
// Local z = 2^n * x
// *************************************************************

edwards25519_decode_nsqr_p25519:

// Copy input argument into q

        movq    (%rdx), %rax
        movq    8(%rdx), %rbx
        movq    16(%rdx), %rcx
        movq    24(%rdx), %rdx
        movq    %rax, Q8(%rsp)
        movq    %rbx, Q8+8(%rsp)
        movq    %rcx, Q8+16(%rsp)
        movq    %rdx, Q8+24(%rsp)

// Main squaring loop, accumulating in u consistently  and
// only ensuring the intermediates are < 2 * p_25519 = 2^256 - 38

edwards25519_decode_loop:
        movq   Q8(%rsp), %rdx
        mulxq  %rdx, %r8, %r15
        mulxq  Q8+0x8(%rsp), %r9, %r10
        mulxq  Q8+0x18(%rsp), %r11, %r12
        movq   Q8+0x10(%rsp), %rdx
        mulxq  Q8+0x18(%rsp), %r13, %r14
        xorl   %ebx, %ebx
        mulxq  Q8(%rsp), %rax, %rcx
        adcxq  %rax, %r10
        adoxq  %rcx, %r11
        mulxq  Q8+0x8(%rsp), %rax, %rcx
        adcxq  %rax, %r11
        adoxq  %rcx, %r12
        movq   Q8+0x18(%rsp), %rdx
        mulxq  Q8+0x8(%rsp), %rax, %rcx
        adcxq  %rax, %r12
        adoxq  %rcx, %r13
        adcxq  %rbx, %r13
        adoxq  %rbx, %r14
        adcq   %rbx, %r14
        xorl   %ebx, %ebx
        adcxq  %r9, %r9
        adoxq  %r15, %r9
        movq   Q8+0x8(%rsp), %rdx
        mulxq  %rdx, %rax, %rdx
        adcxq  %r10, %r10
        adoxq  %rax, %r10
        adcxq  %r11, %r11
        adoxq  %rdx, %r11
        movq   Q8+0x10(%rsp), %rdx
        mulxq  %rdx, %rax, %rdx
        adcxq  %r12, %r12
        adoxq  %rax, %r12
        adcxq  %r13, %r13
        adoxq  %rdx, %r13
        movq   Q8+0x18(%rsp), %rdx
        mulxq  %rdx, %rax, %r15
        adcxq  %r14, %r14
        adoxq  %rax, %r14
        adcxq  %rbx, %r15
        adoxq  %rbx, %r15
        movl   $0x26, %edx
        xorl   %ebx, %ebx
        mulxq  %r12, %rax, %rcx
        adcxq  %rax, %r8
        adoxq  %rcx, %r9
        mulxq  %r13, %rax, %rcx
        adcxq  %rax, %r9
        adoxq  %rcx, %r10
        mulxq  %r14, %rax, %rcx
        adcxq  %rax, %r10
        adoxq  %rcx, %r11
        mulxq  %r15, %rax, %r12
        adcxq  %rax, %r11
        adoxq  %rbx, %r12
        adcxq  %rbx, %r12
        shldq  $0x1, %r11, %r12
        btr    $0x3f, %r11
        movl   $0x13, %edx
        imulq  %r12, %rdx
        addq   %rdx, %r8
        adcq   %rbx, %r9
        adcq   %rbx, %r10
        adcq   %rbx, %r11
        movq   %r8, Q8(%rsp)
        movq   %r9, Q8+0x8(%rsp)
        movq   %r10, Q8+0x10(%rsp)
        movq   %r11, Q8+0x18(%rsp)

// Loop as applicable

        decq    %rsi
        jnz     edwards25519_decode_loop

// We know the intermediate result x < 2^256 - 38, and now we do strict
// modular reduction mod 2^255 - 19. Note x < 2^255 - 19 <=> x + 19 < 2^255
// which is equivalent to a "ns" condition. We just use the results where
// they were in registers [%r11;%r10;%r9;%r8] instead of re-loading them.

        movl    $19, %eax
        xorl    %ebx, %ebx
        xorl    %ecx, %ecx
        xorl    %edx, %edx
        addq    %r8, %rax
        adcq    %r9, %rbx
        adcq    %r10, %rcx
        adcq    %r11, %rdx

        cmovns  %r8, %rax
        cmovns  %r9, %rbx
        cmovns  %r10, %rcx
        cmovns  %r11, %rdx
        btr     $63, %rdx
        movq    %rax, (%rdi)
        movq    %rbx, 8(%rdi)
        movq    %rcx, 16(%rdi)
        movq    %rdx, 24(%rdi)
        ret

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif
