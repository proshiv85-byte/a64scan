// One line per instruction: "<insn> // <expected feature or none>"
.text
.globl _start
_start:
  add x0, x1, x2              // none
  ldr x0, [x1, #8]            // none
  ldr x0, [x1, x2]            // none
  ldxp x0, x1, [x2]           // none
  stxp w3, x0, x1, [x2]       // none
  ldaxr w0, [x1]              // none
  ldar x0, [x1]               // none
  stlr x0, [x1]               // none
  fadd s0, s1, s2             // none
  fadd d0, d1, d2             // none
  fcvt s0, h1                 // none
  fcvt h0, s1                 // none
  fcvt d0, h1                 // none
  fmadd d0, d1, d2, d3        // none
  fadd v0.4s, v1.4s, v2.4s    // none
  mul v0.4s, v1.4s, v2.4s     // none
  mla v0.4s, v1.4s, v2.s[1]   // none
  mul v0.4h, v1.4h, v2.h[1]   // none
  mul v0.4s, v1.4s, v2.s[3]   // none
  fmla v0.4s, v1.4s, v2.s[1]  // none
  sqdmulh v0.8h, v1.8h, v2.h[1] // none
  umull v0.2d, v1.2s, v2.2s   // none
  pmull v0.8h, v1.8b, v2.8b   // none
  udiv x0, x1, x2             // none
  clz x0, x1                  // none
  ret                         // none
  br x3                       // none
  blr x3                      // none
  add x0, x1, #4095, lsl #12  // none
  ldp x29, x30, [sp], #16     // none
  nop                         // none
  udf #0xcafe                 // none
  brk #0x3e8                  // none
  crc32cx w0, w1, x2          // crc
  crc32b w0, w1, w2           // crc
  aese v0.16b, v1.16b         // crypto
  aesimc v0.16b, v1.16b       // crypto
  sha256h q0, q1, v2.4s       // crypto
  sha1su1 v0.4s, v1.4s        // crypto
  pmull v0.1q, v1.1d, v2.1d   // crypto
  ldadd x0, x1, [x2]          // lse
  ldaddal w0, w1, [x2]        // lse
  stclrlb w0, [x1]            // lse
  ldumax x0, x1, [x2]         // lse
  swpal x0, x1, [x2]          // lse
  cas x0, x1, [x2]            // lse
  casal w0, w1, [x2]          // lse
  caspal x0, x1, x2, x3, [x4] // lse
  casb w0, w1, [x2]           // lse
  sqrdmlah v0.8h, v1.8h, v2.8h // rdm
  sqrdmlsh s0, s1, s2         // rdm
  sqrdmlah v0.4s, v1.4s, v2.s[1] // rdm
  fadd h0, h1, h2             // fp16
  fmul h0, h1, h2             // fp16
  fcvtzs w0, h1               // fp16
  fcvtzs x0, h1               // fp16
  scvtf h0, w1                // fp16
  fmov w0, h1                 // fp16
  fmadd h0, h1, h2, h3        // fp16
  fadd v0.8h, v1.8h, v2.8h    // fp16
  fabs v0.4h, v1.4h           // fp16
  fmla v0.8h, v1.8h, v2.h[3]  // fp16
  fabd h0, h1, h2             // fp16
  fcvtzs h0, h1               // fp16
  sdot v0.4s, v1.16b, v2.16b  // dotprod
  udot v0.2s, v1.8b, v2.8b    // dotprod
  sdot v0.4s, v1.16b, v2.4b[1] // dotprod
  eor3 v0.16b, v1.16b, v2.16b, v3.16b // sha3
  sha512h q0, q1, v2.2d       // sha3
  rax1 v0.2d, v1.2d, v2.2d    // sha3
  sm3ss1 v0.4s, v1.4s, v2.4s, v3.4s // sha3
  ldapr x0, [x1]              // rcpc
  ldaprb w0, [x1]             // rcpc
  pacia x0, x1                // pauth
  autdb x0, x1                // pauth
  xpaci x0                    // pauth
  pacga x0, x1, x2            // pauth
  retaa                       // pauth
  braaz x0                    // pauth
  blraa x0, x1                // pauth
  ldraa x0, [x1, #8]          // pauth
  fjcvtzs w0, d1              // jscvt
  fcmla v0.4s, v1.4s, v2.4s, #90 // fcma
  fcadd v0.4s, v1.4s, v2.4s, #270 // fcma
  fcmla v0.4s, v1.4s, v2.s[1], #180 // fcma
  ldapur x0, [x1, #-8]        // rcpc2
  stlurb w0, [x1, #3]         // rcpc2
  cfinv                       // flagm
  rmif x0, #3, #2             // flagm
  setf8 w0                    // flagm
  axflag                      // flagm
  frint32z s0, s1             // frint
  frint64x d0, d1             // frint
  sb                          // sb
  irg x0, x1                  // mte
  addg x0, x1, #16, #1        // mte
  subp x0, x1, x2             // mte
  stg x0, [x1, #16]           // mte
  ldg x0, [x1]                // mte
  st2g x0, [x1], #32          // mte
  bfdot v0.4s, v1.8h, v2.8h   // bf16
  bfmmla v0.4s, v1.8h, v2.8h  // bf16
  bfmlalb v0.4s, v1.8h, v2.8h // bf16
  bfcvt h0, s1                // bf16
  bfcvtn v0.4h, v1.4s         // bf16
  bfdot v0.4s, v1.8h, v2.2h[1] // bf16
  bfmlalt v0.4s, v1.8h, v2.h[5] // bf16
  smmla v0.4s, v1.16b, v2.16b // i8mm
  ummla v0.4s, v1.16b, v2.16b // i8mm
  usmmla v0.4s, v1.16b, v2.16b // i8mm
  usdot v0.4s, v1.16b, v2.16b // i8mm
  sudot v0.4s, v1.16b, v2.4b[1] // i8mm
  usdot v0.2s, v1.8b, v2.4b[3] // i8mm
  ld64b x0, [x1]              // ls64
  st64b x0, [x1]              // ls64
  cpyfp [x0]!, [x1]!, x2!     // mops
  cpyfm [x0]!, [x1]!, x2!     // mops
  cpyp [x0]!, [x1]!, x2!      // mops
  setp [x0]!, x1!, x2         // mops
  sete [x0]!, x1!, x2         // mops
  abs x0, x1                  // cssc
  cnt w0, w1                  // cssc
  ctz x0, x1                  // cssc
  smax x0, x1, x2             // cssc
  umin w0, w1, #200           // cssc
  ptrue p0.s                  // sve
  ld1w {z0.s}, p0/z, [x0]     // sve
  fmla z0.s, p0/m, z1.s, z2.s // sve
  whilelo p0.s, x0, x1        // sve
  sqdmullt z0.h, z1.b, z2.b   // sve
  rdvl x0, #1                 // sve
  smstart                     // sme
  fmopa za0.s, p0/m, p1/m, z0.s, z1.s // sme
  ld1w {za0h.s[w12, 0]}, p0/z, [x0] // sme
  zero {za}                   // sme
  paciasp                     // hint-pauth
  autiasp                     // hint-pauth
  pacibsp                     // hint-pauth
  xpaclri                     // hint-pauth
  bti c                       // hint-bti
  bti jc                      // hint-bti
