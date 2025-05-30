// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Reduce modulo group order, z := x mod n_256
// Input x[k]; output z[4]
//
//    extern void bignum_mod_n256
//     (uint64_t z[static 4], uint64_t k, uint64_t *x);
//
// Reduction is modulo the group order of the NIST curve P-256.
//
// Standard ARM ABI: X0 = z, X1 = k, X2 = x
// ----------------------------------------------------------------------------
#include "_internal_s2n_bignum.h"

        S2N_BN_SYM_VISIBILITY_DIRECTIVE(bignum_mod_n256)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(bignum_mod_n256)
        S2N_BN_SYM_VISIBILITY_DIRECTIVE(bignum_mod_n256_alt)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(bignum_mod_n256_alt)
        .text
        .balign 4

#define z x0
#define k x1
#define x x2

#define m0 x3
#define m1 x4
#define m2 x5
#define m3 x6

#define t0 x7
#define t1 x8
#define t2 x9
#define t3 x10
#define t4 x11

#define n0 x12
#define n1 x13
#define n3 x14

// These two are aliased: we only load d when finished with q

#define q x15
#define d x15

// Loading large constants

#define movbig(nn,n3,n2,n1,n0)                                              \
        movz    nn, n0 __LF                                            \
        movk    nn, n1, lsl #16 __LF                                   \
        movk    nn, n2, lsl #32 __LF                                   \
        movk    nn, n3, lsl #48

S2N_BN_SYMBOL(bignum_mod_n256):

S2N_BN_SYMBOL(bignum_mod_n256_alt):

// If the input is already <= 3 words long, go to a trivial "copy" path

        cmp     k, #4
        bcc     bignum_mod_n256_short

// Otherwise load the top 4 digits (top-down) and reduce k by 4

        sub     k, k, #4
        lsl     t0, k, #3
        add     t0, t0, x
        ldp     m2, m3, [t0, #16]
        ldp     m0, m1, [t0]

// Load the complicated three words of 2^256 - n_256 = [n3; 0; n1; n0]

        movbig( n0, #0x0c46, #0x353d, #0x039c, #0xdaaf)
        movbig( n1, #0x4319, #0x0552, #0x58e8, #0x617b)
        mov     n3, #0x00000000ffffffff

// Reduce the top 4 digits mod n_256 (a conditional subtraction of n_256)

        adds    t0, m0, n0
        adcs    t1, m1, n1
        adcs    t2, m2, xzr
        adcs    t3, m3, n3
        csel    m0, m0, t0, cc
        csel    m1, m1, t1, cc
        csel    m2, m2, t2, cc
        csel    m3, m3, t3, cc

// Now do (k-4) iterations of 5->4 word modular reduction

        cbz     k, bignum_mod_n256_writeback
bignum_mod_n256_loop:

// Writing the input as z = 2^256 * m3 + 2^192 * m2 + t = 2^192 * h + t, our
// intended quotient approximation is MIN ((h + h>>32 + 1)>>64) (2^64 - 1).

        subs    xzr, xzr, xzr   // set carry flag for +1
        extr    q, m3, m2, #32
        adcs    xzr, m2, q
        lsr     q, m3, #32
        adcs    q, m3, q
        csetm   t0, cs
        orr     q, q, t0

// [t4;t3;t2;t1;t0] = q * (2^256 - n_256)

        mul     t0, n0, q
        mul     t1, n1, q
        mul     t3, n3, q
        umulh   t2, n0, q
        adds    t1, t1, t2
        umulh   t2, n1, q
        adc     t2, t2, xzr     // No carry: high of mul + {0,1}
        umulh   t4, n3, q

// Compensate for 2^256 * q

        sub     m3, m3, q

// Decrement k and load the next digit (note that d aliases to q)

        sub     k, k, #1
        ldr     d, [x, k, lsl #3]

// [t4;t3;t2;t1;t0] = [m3;m2;m1;m0;d] - q * n_256

        adds    t0, d, t0
        adcs    t1, m0, t1
        adcs    t2, m1, t2
        adcs    t3, m2, t3
        adc     t4, m3, t4

// Now our top word t4 is either zero or all 1s. Use it for a masked
// addition of n_256, which we can do by a *subtraction* of
// 2^256 - n_256 from our portion, re-using the constants

        and     d, t4, n0
        subs    m0, t0, d
        and     d, t4, n1
        sbcs    m1, t1, d
        sbcs    m2, t2, xzr
        and     d, t4, n3
        sbc     m3, t3, d

        cbnz    k, bignum_mod_n256_loop

// Finally write back [m3;m2;m1;m0] and return

bignum_mod_n256_writeback:
        stp     m0, m1, [z]
        stp     m2, m3, [z, #16]
        ret

// Short case: just copy the input with zero-padding

bignum_mod_n256_short:
        mov     m0, xzr
        mov     m1, xzr
        mov     m2, xzr
        mov     m3, xzr

        cbz     k, bignum_mod_n256_writeback
        ldr     m0, [x]
        subs    k, k, #1
        beq     bignum_mod_n256_writeback
        ldr     m1, [x, #8]
        subs    k, k, #1
        beq     bignum_mod_n256_writeback
        ldr     m2, [x, #16]
        b       bignum_mod_n256_writeback

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
