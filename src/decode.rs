//! Classify one AArch64 instruction word by the architecture extension it needs.
//!
//! Only encodings that are UNDEFINED on a plain ARMv8.0-A core are reported
//! (plus the optional v8.0 extensions CRC32 and Crypto, and the hint-space
//! PAC/BTI instructions, which execute as NOPs on older cores). Patterns follow
//! the Arm ARM encoding tables; `tests/fixtures/vectors.tsv` (assembled with
//! GNU as) is the ground truth for every pattern.

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Feature {
    Crc,
    Crypto,
    Lse,
    Rdm,
    Fp16,
    DotProd,
    Sha3,
    Sve,
    Rcpc,
    PAuth,
    Jscvt,
    Fcma,
    Rcpc2,
    FlagM,
    Frint,
    Sb,
    Mte,
    Bf16,
    I8mm,
    Ls64,
    Mops,
    Cssc,
    Sme,
    Lor,
    Hbc,
    Rcpc3,
    Cpa,
    Fp8,
    Lsui,
    Cmpbr,
    Fhm,
    Lsfe,
    Lse128,
    HintPauth,
    HintBti,
}

pub const ALL: [Feature; 35] = [
    Feature::Crc,
    Feature::Crypto,
    Feature::Lse,
    Feature::Rdm,
    Feature::Fp16,
    Feature::DotProd,
    Feature::Sha3,
    Feature::Sve,
    Feature::Rcpc,
    Feature::PAuth,
    Feature::Jscvt,
    Feature::Fcma,
    Feature::Rcpc2,
    Feature::FlagM,
    Feature::Frint,
    Feature::Sb,
    Feature::Mte,
    Feature::Bf16,
    Feature::I8mm,
    Feature::Ls64,
    Feature::Mops,
    Feature::Cssc,
    Feature::Sme,
    Feature::Lor,
    Feature::Hbc,
    Feature::Rcpc3,
    Feature::Cpa,
    Feature::Fp8,
    Feature::Lsui,
    Feature::Cmpbr,
    Feature::Fhm,
    Feature::Lsfe,
    Feature::Lse128,
    Feature::HintPauth,
    Feature::HintBti,
];

impl Feature {
    pub fn name(self) -> &'static str {
        use Feature::*;
        match self {
            Crc => "crc",
            Crypto => "crypto",
            Lse => "lse",
            Rdm => "rdm",
            Fp16 => "fp16",
            DotProd => "dotprod",
            Sha3 => "sha3",
            Sve => "sve",
            Rcpc => "rcpc",
            PAuth => "pauth",
            Jscvt => "jscvt",
            Fcma => "fcma",
            Rcpc2 => "rcpc2",
            FlagM => "flagm",
            Frint => "frint",
            Sb => "sb",
            Mte => "mte",
            Bf16 => "bf16",
            I8mm => "i8mm",
            Ls64 => "ls64",
            Mops => "mops",
            Cssc => "cssc",
            Sme => "sme",
            Lor => "lor",
            Hbc => "hbc",
            Rcpc3 => "rcpc3",
            Cpa => "cpa",
            Fp8 => "fp8",
            Lsui => "lsui",
            Cmpbr => "cmpbr",
            Fhm => "fhm",
            Lsfe => "lsfe",
            Lse128 => "lse128",
            HintPauth => "hint-pauth",
            HintBti => "hint-bti",
        }
    }

    /// Architecture version that introduced the extension, as (8, minor).
    /// ARMv9.x is mapped to its ARMv8 equivalent: v9.0 = v8.5 ... v9.4 = v8.9, v9.5 = (8, 10), v9.6 = (8, 11).
    pub fn since(self) -> (u8, u8) {
        use Feature::*;
        match self {
            Crc | Crypto => (8, 0),
            Lse | Rdm | Lor => (8, 1),
            Fp16 | DotProd | Sha3 | Sve | Fhm => (8, 2),
            Rcpc | PAuth | Jscvt | Fcma | HintPauth => (8, 3),
            Rcpc2 | FlagM => (8, 4),
            Frint | Sb | Mte | HintBti => (8, 5),
            Bf16 | I8mm => (8, 6),
            Ls64 | Sme => (8, 7),
            Mops | Hbc => (8, 8),
            Cssc | Rcpc3 | Lse128 => (8, 9),
            Cpa | Fp8 => (8, 10),
            Lsui | Cmpbr | Lsfe => (8, 11),
        }
    }

    pub fn since_str(self) -> &'static str {
        use Feature::*;
        match self {
            Sme => "v9.2",
            Cssc | Rcpc3 => "v8.9",
            Lse128 => "v9.4",
            Cpa | Fp8 => "v9.5",
            Lsui | Cmpbr | Lsfe => "v9.6",
            _ => match self.since() {
                (8, 0) => "v8.0*",
                (8, 1) => "v8.1",
                (8, 2) => "v8.2",
                (8, 3) => "v8.3",
                (8, 4) => "v8.4",
                (8, 5) => "v8.5",
                (8, 6) => "v8.6",
                (8, 7) => "v8.7",
                (8, 8) => "v8.8",
                _ => "v8.9",
            },
        }
    }

    pub fn description(self) -> &'static str {
        use Feature::*;
        match self {
            Crc => "CRC32/CRC32C (optional in v8.0)",
            Crypto => "AES, SHA1, SHA256, PMULL.1Q (optional in v8.0)",
            Lse => "large system extensions: LDADD/SWP/CAS... atomics",
            Rdm => "SQRDMLAH/SQRDMLSH",
            Fp16 => "half-precision FP arithmetic (scalar and vector)",
            DotProd => "SDOT/UDOT",
            Sha3 => "SHA3, SHA512, SM3, SM4",
            Sve => "Scalable Vector Extension (SVE/SVE2)",
            Rcpc => "LDAPR (load-acquire RCpc)",
            PAuth => "pointer authentication, non-hint forms (RETAA, PACGA, LDRAA, RETAASPPC...)",
            Jscvt => "FJCVTZS",
            Fcma => "FCMLA/FCADD complex numbers",
            Rcpc2 => "LDAPUR/STLUR (unscaled RCpc)",
            FlagM => "CFINV, RMIF, SETF8/16, AXFLAG/XAFLAG",
            Frint => "FRINT32/FRINT64",
            Sb => "SB speculation barrier",
            Mte => "memory tagging: IRG, ADDG, STG, LDG, SUBP, ...",
            Bf16 => "BFloat16: BFDOT, BFMMLA, BFMLAL, BFCVT",
            I8mm => "int8 matrix multiply: SMMLA, UMMLA, USMMLA, USDOT, SUDOT",
            Ls64 => "LD64B/ST64B and other o3=1 atomic-space forms",
            Mops => "memcpy/memset instructions: CPY*, SET*",
            Cssc => "ABS, CNT, CTZ, SMAX/SMIN/UMAX/UMIN (common short sequence)",
            Sme => "Scalable Matrix Extension: SMSTART, FMOPA, ZA loads, ...",
            Lor => "limited ordering regions: LDLAR/STLLR",
            Hbc => "hinted conditional branch BC.cond",
            Rcpc3 => "RCpc3: SIMD LDAPUR/STLUR, LDIAPP/STILP, LDAPR/STLR writeback",
            Cpa => "checked pointer arithmetic: ADDPT/SUBPT/MADDPT/MSUBPT",
            Fp8 => "FP8, LUT, FSCALE (v9.5 SIMD): FDOT, FMLALL*, LUTI2/4, ...",
            Lsui => "unprivileged loads/stores: LDTP/STTP, LDTXR, CAST, ...",
            Cmpbr => "compare and branch: CBGT/CBEQ/CBBxx/CBHxx",
            Fhm => "FMLAL/FMLSL (half-precision multiply-add long)",
            Lsfe => "floating-point atomics: LDFADD, LDFMAX, STFADD, ...",
            Lse128 => "128-bit atomics and RCW: LDSETP, SWPP, RCWCAS, RCWSWP, ...",
            HintPauth => "PACIASP/AUTIASP/... in hint space (NOP without PAC)",
            HintBti => "BTI landing pads (NOP without BTI)",
        }
    }

    /// Executes as a NOP on cores without the extension.
    pub fn is_hint(self) -> bool {
        matches!(self, Feature::HintPauth | Feature::HintBti)
    }

    pub fn from_name(s: &str) -> Option<Feature> {
        ALL.iter().copied().find(|f| f.name().eq_ignore_ascii_case(s))
    }
}

#[inline]
fn m(w: u32, mask: u32, val: u32) -> bool {
    w & mask == val
}

/// The extension `w` needs beyond ARMv8.0-A, or None for base v8.0 (or an
/// encoding this scanner does not know).
pub fn classify(w: u32) -> Option<Feature> {
    use Feature::*;
    let op0 = (w >> 25) & 0xF;

    // Top-level SVE space (op0 = 0010) and SME space (op0 = 0000 with bit 31 set).
    if op0 == 0b0010 {
        return Some(Sve);
    }
    if op0 == 0 {
        return if w >> 31 == 1 { Some(Sme) } else { None };
    }

    // ---- Branches, exceptions, system (op0 = 101x)
    if op0 & 0b1110 == 0b1010 {
        // HINT space: NOPs on cores that lack the feature
        if m(w, 0xFFFF_F01F, 0xD503_201F) {
            return match (w >> 5) & 0x7F {
                7 | 8 | 10 | 12 | 14 | 24..=31 => Some(HintPauth),
                32 | 34 | 36 | 38 => Some(HintBti),
                _ => None,
            };
        }
        if w == 0xD503_30FF {
            return Some(Sb);
        }
        if w == 0xD500_401F || w == 0xD500_403F || w == 0xD500_405F {
            return Some(FlagM); // CFINV, XAFLAG, AXFLAG
        }
        if m(w, 0xFFFF_F8FF, 0xD503_407F) {
            return Some(Sme); // MSR SVCR*: SMSTART/SMSTOP
        }
        if m(w, 0xFFC0_001F, 0x5500_001F) {
            return Some(PAuth); // RETAASPPC/RETABSPPC (PAuth_LR)
        }
        if m(w, 0xFF00_0010, 0x5400_0010) {
            return Some(Hbc); // BC.cond
        }
        if m(w, 0x7E00_0000, 0x7400_0000) {
            return Some(Cmpbr); // CB<cc> (register and immediate)
        }
        // BRAA/BRAB/BLRAA/RETAA/ERETAA...: unconditional branch (register), op3 = 00001x
        if m(w, 0xFE1F_F800, 0xD61F_0800) {
            return Some(PAuth);
        }
        return None;
    }

    // ---- Loads and stores (op0 = x1x0)
    if op0 & 0b0101 == 0b0100 {
        if m(w, 0xFF20_0000, 0xD920_0000) {
            return Some(Mte); // STG/LDG/STZG/ST2G/STGM/LDGM...
        }
        if m(w, 0xBF20_0000, 0x1920_0000) {
            // 0 S 011001 A R 1 Rs ...: LDTADD.. (bits 11:10 = 01), LSE128 / RCW (00, 10)
            return Some(if (w >> 10) & 3 == 1 { Lsui } else { Lse128 });
        }
        if m(w, 0xFA00_0000, 0xE800_0000) || m(w, 0x3F00_0000, 0x0900_0000) {
            return Some(Lsui); // LDTP/STTP/LDTNP/STTNP (opc=11 pair, GPR+SIMD), LDTXR/CAST (001001), LDTADD...
        }
        if matches!(w & 0xFFC0_0000, 0x6880_0000 | 0x6980_0000 | 0x6900_0000) {
            return Some(Mte); // STGP
        }
        if m(w, 0x3FA0_8000, 0x0880_0000) {
            return Some(Lor); // LDLAR/STLLR (ordered, o0 = 0)
        }
        if m(w, 0x3B20_0C00, 0x1900_0800) {
            return Some(Rcpc3);
        }
        if m(w, 0x3F20_0C00, 0x3C20_0000) {
            return Some(Lsfe); // FP atomics: atomic memory space with V = 1
        }
        // Atomic memory operations: size 111 V 00 A R 1 Rs o3 opc 00 Rn Rt
        if m(w, 0x3F20_0C00, 0x3820_0000) {
            let o3 = (w >> 15) & 1;
            let opc = (w >> 12) & 7;
            return Some(match (o3, opc) {
                (0, _) | (1, 0) => Lse,
                (1, 4) => Rcpc,
                _ => Ls64,
            });
        }
        if m(w, 0x3FA0_7C00, 0x08A0_7C00) || m(w, 0xBFA0_7C00, 0x0820_7C00) {
            return Some(Lse); // CAS, CASP
        }
        if m(w, 0x3F20_0C00, 0x1900_0000) {
            return Some(Rcpc2); // LDAPUR/STLUR
        }
        if m(w, 0x3B20_0C00, 0x1900_0400) || m(w, 0xFFE0_0C00, 0x1DC0_0000) {
            return Some(Mops); // CPY*/SET*, SETGO*
        }
        if m(w, 0xFF20_0400, 0xF820_0400) {
            return Some(PAuth); // LDRAA/LDRAB
        }
        return None;
    }

    // ---- Data processing, immediate (op0 = 100x)
    if op0 & 0b1110 == 0b1000 {
        if m(w, 0xBFC0_0000, 0x9180_0000) {
            return Some(Mte); // ADDG/SUBG (bits 15:14 are should-be-zero, not fixed)
        }
        if m(w, 0xFFC0_001F, 0xF380_001F) {
            return Some(PAuth); // AUTIASPPC/AUTIBSPPC (PAuth_LR)
        }
        if m(w, 0x7FC0_0000, 0x11C0_0000) {
            return Some(Cssc); // SMAX/UMAX/SMIN/UMIN (immediate)
        }
        return None;
    }

    // ---- Data processing, register (op0 = x101)
    if op0 & 0b0111 == 0b0101 {
        if m(w, 0xFFE0_0000, 0x9B60_0000) || m(w, 0xBFE0_E000, 0x9A00_2000) {
            return Some(Cpa); // MADDPT/MSUBPT, ADDPT/SUBPT
        }
        if m(w, 0xFFFF_0000, 0xDAC1_0000) && (w >> 10) & 0x3F <= 0x11 {
            return Some(PAuth); // PACIA...AUTDZB, XPACI/XPACD
        }
        if m(w, 0xFFE0_FC00, 0x9AC0_3000) {
            return Some(PAuth); // PACGA
        }
        if m(w, 0xFFE0_F800, 0x9AC0_1000) || m(w, 0xDFE0_FC00, 0x9AC0_0000) {
            return Some(Mte); // IRG/GMI, SUBP/SUBPS
        }
        if m(w, 0x7FFF_0000, 0x5AC0_0000) && matches!((w >> 10) & 0x3F, 6..=8) {
            return Some(Cssc); // CTZ, CNT, ABS
        }
        if m(w, 0x7FE0_F000, 0x1AC0_6000) {
            return Some(Cssc); // SMAX/UMAX/SMIN/UMIN (register)
        }
        if m(w, 0x7FE0_E000, 0x1AC0_4000) {
            return Some(Crc); // opcode 010 C sz
        }
        if m(w, 0xFFE0_7C10, 0xBA00_0400) || m(w, 0xFFFF_BC1F, 0x3A00_080D) {
            return Some(FlagM); // RMIF, SETF8/SETF16
        }
        return None;
    }

    // ---- Scalar FP and Advanced SIMD (op0 = x111)
    if op0 & 0b0111 == 0b0111 {
        return classify_simd_fp(w);
    }
    None
}

fn classify_simd_fp(w: u32) -> Option<Feature> {
    use Feature::*;
    // crypto
    if m(w, 0xFF00_0000, 0xCE00_0000) {
        return Some(Sha3); // SHA512, SHA3 (EOR3/RAX1/XAR/BCAX), SM3, SM4
    }
    if m(w, 0xFFFF_CC00, 0x4E28_4800)          // AESE/AESD/AESMC/AESIMC
        || m(w, 0xFFE0_8C00, 0x5E00_0000)      // SHA1/SHA256 three-register
        || m(w, 0xFFFE_0C00, 0x5E28_0800)      // SHA1/SHA256 two-register
        || m(w, 0xBFE0_FC00, 0x0EE0_E000)
    // PMULL/PMULL2 .1q
    {
        return Some(Crypto);
    }

    // scalar FP conversions and specials
    if m(w, 0xFFFF_FC00, 0x1E7E_0000) {
        return Some(Jscvt);
    }
    if m(w, 0xFFFF_FC00, 0x1E63_4000) {
        return Some(Bf16); // BFCVT
    }
    if m(w, 0xFFBE_7C00, 0x1E28_4000) {
        return Some(Frint); // FRINT32Z/X, FRINT64Z/X (scalar)
    }

    // scalar FP with ftype = 11 (half precision); FCVT from half is v8.0
    if m(w, 0x7FC0_0000, 0x1EC0_0000) {
        let fcvt = m(w, 0xFFFE_7C00, 0x1EE2_4000); // FCVT Sd/Dd, Hn (opcode 00010x)
        return if fcvt { None } else { Some(Fp16) };
    }
    if m(w, 0xFFC0_0000, 0x1FC0_0000) {
        return Some(Fp16); // FMADD/FMSUB/FNMADD/FNMSUB h
    }

    // SCVTF/UCVTF/FCVTZS/FCVTZU (fixed-point) .h: shift by immediate with immh = 001x
    if m(w, 0x9FF0_FC00, 0x0F10_E400) || m(w, 0x9FF0_FC00, 0x0F10_FC00)
        || m(w, 0xDFF0_FC00, 0x5F10_E400) || m(w, 0xDFF0_FC00, 0x5F10_FC00)
    {
        return Some(Fp16);
    }
    // FP16 across lanes (FMAXNMV/FMINNMV/FMAXV/FMINV with U = 0), FMOV .4h/.8h immediate
    if m(w, 0xBF3F_EC00, 0x0E30_C800) || m(w, 0xBF3F_FC00, 0x0E30_F800) || m(w, 0xBFF8_FC00, 0x0F00_FC00) {
        return Some(Fp16);
    }
    if m(w, 0x9FBF_EC00, 0x0E21_E800) {
        return Some(Frint); // FRINT32Z/X, FRINT64Z/X (vector)
    }
    // Advanced SIMD three-same FP16, two-register misc FP16 (vector + scalar)
    if m(w, 0x9F60_C400, 0x0E40_0400)
        || m(w, 0x9F7E_0C00, 0x0E78_0800)
        || m(w, 0xDF60_C400, 0x5E40_0400)
        || m(w, 0xDF7E_0C00, 0x5E78_0800)
    {
        return Some(Fp16);
    }

    // FHM: FMLAL/FMLSL (U=0, opcode 11101), FMLAL2/FMLSL2 (U=1, opcode 11001); size<0> = 0
    if m(w, 0xBF60_FC00, 0x0E20_EC00) || m(w, 0xBF60_FC00, 0x2E20_CC00) {
        return Some(Fhm);
    }
    // FP8 (three-same extra, U=0): FDOT/FMLALB/T (1111), FMLALL** (1000), FMMLA (1101, Q=1, U any),
    // FAMAX/FAMIN (three-same, a=1, opcode 11011), FCVTN (FP8, 1110 1)
    if m(w, 0xBF20_FC00, 0x0E00_FC00) || m(w, 0xBF20_FC00, 0x0E00_C400) || m(w, 0xFF20_FC00, 0x4E00_EC00) || m(w, 0xFFE0_FC00, 0x6E00_EC00)
        || m(w, 0x9FA0_FC00, 0x0EA0_DC00) || m(w, 0xBF20_FC00, 0x0E00_F400)
    {
        return Some(Fp8);
    }
    // FSCALE (vector, U=1 a=1 opcode 11111); LUTI2/LUTI4 (TBL space with size != 00)
    if m(w, 0xBFA0_FC00, 0x2EA0_FC00) || (m(w, 0xBF20_8C00, 0x0E00_0000) && (w >> 22) & 3 != 0) {
        return Some(Fp8);
    }

    // three-same (extra), size-specific: BF16, I8MM, DotProd, RDM, FCMA
    if m(w, 0xBFE0_FC00, 0x2E40_FC00) || m(w, 0xFFE0_FC00, 0x6E40_EC00) || m(w, 0xBFE0_FC00, 0x2EC0_FC00) {
        return Some(Bf16); // BFDOT, BFMMLA, BFMLALB/T
    }
    if m(w, 0xBFFF_FC00, 0x0EA1_6800) {
        return Some(Bf16); // BFCVTN/BFCVTN2
    }
    if m(w, 0xFFE0_FC00, 0x4E80_A400) || m(w, 0xFFE0_FC00, 0x6E80_A400) || m(w, 0xFFE0_FC00, 0x4E80_AC00) {
        return Some(I8mm); // SMMLA, UMMLA, USMMLA
    }
    if m(w, 0xBFE0_FC00, 0x0E80_9C00) {
        return Some(I8mm); // USDOT (vector)
    }
    if m(w, 0x9FE0_FC00, 0x0E80_9400) {
        return Some(DotProd); // SDOT/UDOT (vector)
    }
    if m(w, 0xBF20_F400, 0x2E00_8400) || m(w, 0xFF20_F400, 0x7E00_8400) {
        return Some(Rdm); // SQRDMLAH/SQRDMLSH vector, scalar
    }
    if m(w, 0xBF20_E400, 0x2E00_C400) || m(w, 0xBF20_EC00, 0x2E00_E400) {
        return Some(Fcma); // FCMLA, FCADD
    }

    // by element (vector: 0 Q U 01111 size L M Rm opcode H 0 Rn Rd)
    if m(w, 0x9F00_0400, 0x0F00_0000) {
        let u = (w >> 29) & 1;
        let size = (w >> 22) & 3;
        let opc = (w >> 12) & 0xF;
        return match (u, size, opc) {
            (0, 0b00, 0b0001 | 0b0101 | 0b1001) | (1, 0b00, 0b1001) => Some(Fp16), // FMLA/FMLS/FMUL/FMULX .h
            (0, 0b10, 0b0000 | 0b0100) | (1, 0b10, 0b1000 | 0b1100) => Some(Fhm),    // FMLAL/FMLSL(2) by element
            (0, 0b00 | 0b01 | 0b11, 0b0000) | (1, 0b00 | 0b01, 0b1000) => Some(Fp8),  // FDOT, FMLALB/T, FMLALL** by element (U=0 1000 is MUL)
            (0, 0b00 | 0b10, 0b1111) => Some(I8mm),                               // SUDOT, USDOT
            (0, 0b01 | 0b11, 0b1111) => Some(Bf16),                               // BFDOT, BFMLALB/T
            (_, 0b10, 0b1110) => Some(DotProd),                                   // SDOT/UDOT
            (1, 0b01 | 0b10, 0b1101 | 0b1111) => Some(Rdm),                       // SQRDMLAH/SQRDMLSH
            (1, 0b01 | 0b10, 0b0001 | 0b0011 | 0b0101 | 0b0111) => Some(Fcma),    // FCMLA
            _ => None,
        };
    }
    // scalar by element (01 U 11111 size ...)
    if m(w, 0xDF00_0400, 0x5F00_0000) {
        let u = (w >> 29) & 1;
        let size = (w >> 22) & 3;
        let opc = (w >> 12) & 0xF;
        return match (u, size, opc) {
            (0, 0b00, 0b0001 | 0b0101 | 0b1001) | (1, 0b00, 0b1001) => Some(Fp16),
            (1, 0b01 | 0b10, 0b1101 | 0b1111) => Some(Rdm),
            _ => None,
        };
    }
    None
}

/// Words that are almost never real code next to a real instruction: UDF and the
/// rest of the reserved op0 = 0000 space (small integers, constant data), BRK, and
/// top bytes 0x3E/0x3F/0xBE/0xBF (unallocated scalar-FP space with S or M set),
/// which is where float constants and the high words of doubles land.
#[inline]
pub fn looks_like_data_or_trap(w: u32) -> bool {
    (w >> 25) & 0xF == 0 && w >> 31 == 0
        || m(w, 0xFFE0_001F, 0xD420_0000)
        || matches!(w >> 24, 0x3E | 0x3F | 0xBE | 0xBF)
}

/// Clang -fsanitize=function prologue: this magic word, then a 32-bit type hash,
/// placed in front of the function entry.
pub const UBSAN_FUNCTION_SIG: u32 = 0xC105_CAFE;

/// Control never falls through this word: RET/BR/B (any form), UDF, BRK.
#[inline]
pub fn is_terminator(w: u32) -> bool {
    m(w, 0xFFFF_FC1F, 0xD65F_0000)              // RET
        || m(w, 0xFFFF_FBFF, 0xD65F_0BFF)       // RETAA/RETAB
        || m(w, 0xFFFF_FC1F, 0xD61F_0000)       // BR
        || m(w, 0xFC00_0000, 0x1400_0000)       // B
        || looks_like_data_or_trap(w)
}

/// Target word index of a direct branch or ADR at word index `i`, if any.
#[inline]
pub fn branch_target(w: u32, i: usize) -> Option<i64> {
    let sext = |v: u32, bits: u32| ((v << (32 - bits)) as i32 >> (32 - bits)) as i64;
    let off = if m(w, 0x7C00_0000, 0x1400_0000) {
        sext(w & 0x03FF_FFFF, 26) // B, BL
    } else if m(w, 0xFF00_0000, 0x5400_0000) || m(w, 0x7E00_0000, 0x3400_0000) {
        sext((w >> 5) & 0x7_FFFF, 19) // B.cond/BC.cond, CBZ/CBNZ
    } else if m(w, 0x7E00_0000, 0x3600_0000) {
        sext((w >> 5) & 0x3FFF, 14) // TBZ/TBNZ
    } else if m(w, 0x9F00_0000, 0x1000_0000) {
        let imm = ((w >> 5) & 0x7_FFFF) << 2 | (w >> 29) & 3; // ADR (byte offset)
        let b = sext(imm, 21);
        if b & 3 != 0 {
            return None;
        }
        b >> 2
    } else {
        return None;
    };
    Some(i as i64 + off)
}

/// Typical first instruction of a function: PACIASP/PACIBSP, BTI c/jc,
/// STP x29, x30, [sp, #-n]!, SUB sp, sp, #n.
#[inline]
pub fn is_function_entry(w: u32) -> bool {
    w == 0xD503_233F || w == 0xD503_237F
        || matches!(w, 0xD503_245F | 0xD503_24DF)
        || m(w, 0xFFC0_7FFF, 0xA980_7BFD)
        || m(w, 0xFF80_03FF, 0xD100_03FF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembler_vectors() {
        let mut bad = Vec::new();
        let mut n = 0;
        for line in include_str!("../tests/fixtures/vectors.tsv").lines() {
            let f: Vec<&str> = line.splitn(3, '\t').collect();
            let w = u32::from_str_radix(f[0], 16).unwrap();
            let want = if f[1] == "none" { None } else { Some(Feature::from_name(f[1]).expect(f[1])) };
            let got = classify(w);
            if got != want {
                bad.push(format!("{:08x} {:<40} want {:?} got {:?}", w, f[2], want, got));
            }
            n += 1;
        }
        assert!(n > 100);
        assert!(bad.is_empty(), "{} of {} wrong:\n{}", bad.len(), n, bad.join("\n"));
    }

    #[test]
    fn names_round_trip() {
        for f in ALL {
            assert_eq!(Feature::from_name(f.name()), Some(f));
        }
    }
}
