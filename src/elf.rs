//! Minimal little-endian ELF reader: executable ranges, function symbols and
//! ARM mapping symbols ($x code / $d data). No external dependencies.

pub enum Kind {
    A64,
    A32,
    Other,
}

pub struct CodeRange {
    pub addr: u64,
    pub off: usize,
    pub len: usize,
}

pub struct Parsed {
    pub kind: Kind,
    pub code: Vec<CodeRange>,
    /// (addr, size, name) of STT_FUNC symbols, sorted by addr
    pub funcs: Vec<(u64, u64, String)>,
    /// (addr, is_data) ARM mapping symbols, sorted by addr; empty when stripped
    pub mapping: Vec<(u64, bool)>,
}

const EM_ARM: u16 = 40;
const EM_AARCH64: u16 = 183;
const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const SHT_NOBITS: u32 = 8;
const SHF_EXECINSTR: u64 = 4;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;

fn u16_(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn u32_(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn u64_(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

pub fn is_elf(d: &[u8]) -> bool {
    d.len() >= 20 && &d[..4] == b"\x7fELF"
}

pub fn parse(d: &[u8]) -> Option<Parsed> {
    if !is_elf(d) || d[5] != 1 {
        return None; // big-endian ELF: not handled
    }
    let machine = u16_(d, 18)?;
    if d[4] != 2 || machine != EM_AARCH64 {
        let kind = if machine == EM_ARM || (d[4] == 1 && machine == EM_AARCH64) { Kind::A32 } else { Kind::Other };
        return Some(Parsed { kind, code: vec![], funcs: vec![], mapping: vec![] });
    }

    let mut p = Parsed { kind: Kind::A64, code: vec![], funcs: vec![], mapping: vec![] };
    let shoff = u64_(d, 40)? as usize;
    let shentsize = u16_(d, 58)? as usize;
    let shnum = u16_(d, 60)? as usize;
    let sh = |i: usize| shoff + i * shentsize;

    if shoff != 0 && shnum != 0 && shentsize >= 64 {
        for i in 0..shnum {
            let o = sh(i);
            let ty = u32_(d, o + 4)?;
            let flags = u64_(d, o + 8)?;
            let addr = u64_(d, o + 16)?;
            let off = u64_(d, o + 24)? as usize;
            let size = u64_(d, o + 32)? as usize;
            if flags & SHF_EXECINSTR != 0 && ty != SHT_NOBITS && size > 0 && off.checked_add(size)? <= d.len() {
                p.code.push(CodeRange { addr, off, len: size });
            }
            if ty == SHT_SYMTAB || ty == SHT_DYNSYM {
                read_symbols(d, o, sh, &mut p);
            }
        }
    }
    if p.code.is_empty() {
        // no section headers (or no executable sections): executable PT_LOAD segments
        let phoff = u64_(d, 32)? as usize;
        let phentsize = u16_(d, 54)? as usize;
        let phnum = u16_(d, 56)? as usize;
        for i in 0..phnum {
            let o = phoff + i * phentsize;
            if u32_(d, o)? == PT_LOAD && u32_(d, o + 4)? & PF_X != 0 {
                let off = u64_(d, o + 8)? as usize;
                let addr = u64_(d, o + 16)?;
                let len = u64_(d, o + 32)? as usize;
                if off.checked_add(len)? <= d.len() {
                    p.code.push(CodeRange { addr, off, len });
                }
            }
        }
    }
    p.funcs.sort_by_key(|f| f.0);
    p.funcs.dedup_by_key(|f| f.0);
    p.mapping.sort_by_key(|m| m.0);
    Some(p)
}

fn read_symbols(d: &[u8], o: usize, sh: impl Fn(usize) -> usize, p: &mut Parsed) -> Option<()> {
    let off = u64_(d, o + 24)? as usize;
    let size = u64_(d, o + 32)? as usize;
    let link = u32_(d, o + 40)? as usize;
    let str_off = u64_(d, sh(link) + 24)? as usize;
    let str_size = u64_(d, sh(link) + 32)? as usize;
    let strtab = d.get(str_off..str_off.checked_add(str_size)?)?;
    let syms = d.get(off..off.checked_add(size)?)?;
    for s in syms.chunks_exact(24) {
        let name_off = u32_(s, 0)? as usize;
        let info = s[4];
        let shndx = u16_(s, 6)?;
        let value = u64_(s, 8)?;
        let ssize = u64_(s, 16)?;
        if shndx == 0 {
            continue; // undefined
        }
        let name = strtab.get(name_off..).and_then(|t| t.split(|&b| b == 0).next()).unwrap_or(&[]);
        match name {
            [b'$', b'x', ..] => p.mapping.push((value, false)),
            [b'$', b'd', ..] => p.mapping.push((value, true)),
            _ if info & 0xF == 2 => p.funcs.push((value, ssize, String::from_utf8_lossy(name).into_owned())),
            _ => {}
        }
    }
    Some(())
}

impl Parsed {
    /// True if mapping symbols say `addr` is data. None when there are no mapping symbols.
    pub fn is_data(&self, addr: u64) -> Option<bool> {
        if self.mapping.is_empty() {
            return None;
        }
        let i = self.mapping.partition_point(|m| m.0 <= addr);
        Some(if i == 0 { false } else { self.mapping[i - 1].1 })
    }

    /// A function symbol starts in (addr, addr + n].
    pub fn starts_function_within(&self, addr: u64, n: u64) -> bool {
        let i = self.funcs.partition_point(|f| f.0 <= addr);
        self.funcs.get(i).is_some_and(|f| f.0 <= addr + n)
    }

    /// "symbol+0xoff" for an address, if a function symbol covers it.
    pub fn symbolize(&self, addr: u64) -> Option<String> {
        let i = self.funcs.partition_point(|f| f.0 <= addr);
        let (start, size, name) = self.funcs.get(i.checked_sub(1)?)?;
        if *size == 0 || addr < start + size {
            Some(format!("{}+{:#x}", name, addr - start))
        } else {
            None
        }
    }
}
