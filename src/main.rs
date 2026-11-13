mod decode;
mod elf;

use clap::Parser;
use decode::{ALL, Feature, UBSAN_FUNCTION_SIG, branch_target, classify, is_function_entry, is_terminator, looks_like_data_or_trap};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

const NF: usize = ALL.len();

/// Find AArch64 instructions a target CPU can't execute.
///
/// Scans the executable sections of AArch64 ELF files (recursively for
/// directories) and reports instructions from extensions newer than the target:
/// LSE atomics, RCpc, FP16, dot product, SVE/SVE2, SME, MTE, BF16, I8MM, MOPS, ...
/// Typical use: before porting a ROM built for a newer SoC to an older phone.
///
/// Hits that look like data in the code section (next to UDF/BRK, reserved
/// encodings or ASCII text) are counted as "suspect" and kept separate. When
/// the binary has ARM mapping symbols ($x/$d), data regions are skipped exactly.
///
/// Exit status: 0 = nothing beyond the target, 1 = unsupported instructions
/// found (suspect hits don't count), 2 = error.
#[derive(Parser)]
#[command(version, after_help = "Features: crc crypto lse rdm fp16 dotprod sha3 sve rcpc pauth jscvt fcma rcpc2 flagm frint sb mte bf16 i8mm ls64 mops cssc sme lor hbc rcpc3 cpa fp8 lsui cmpbr fhm lsfe lse128 hint-pauth hint-bti\n\nExamples:\n  a64scan system/                      # what a plain ARMv8.0+crc+crypto core can't run\n  a64scan --allow lse,rcpc,fp16,dotprod system/   # ... when the kernel emulates those\n  a64scan --upto v8.2 --deny sve vendor/lib64/\n  a64scan -l --max-list 5 libfoo.so    # list each hit with its address and symbol\n  a64scan --decode d503233f 4e80a400")]
struct Args {
    /// Files or directories to scan
    #[arg(required_unless_present_any = ["decode", "decode_file"])]
    paths: Vec<PathBuf>,

    /// Extensions the target supports (natively or emulated), comma-separated
    #[arg(short, long, value_delimiter = ',', default_value = "crc,crypto")]
    allow: Vec<String>,

    /// Also allow every extension up to this architecture version (e.g. v8.2; v9.x = v8.(x+5))
    #[arg(long, value_name = "VERSION")]
    upto: Option<String>,

    /// Extensions to report even if --allow/--upto allowed them
    #[arg(long, value_delimiter = ',')]
    deny: Vec<String>,

    /// Report hint-space PAC/BTI instructions (NOPs on cores without them)
    #[arg(long)]
    hints: bool,

    /// List each hit: address, word, extension, symbol
    #[arg(short, long)]
    list: bool,

    /// Maximum hits listed per file with --list (0 = all)
    #[arg(long, default_value_t = 20)]
    max_list: usize,

    /// Also show files whose only hits are suspect
    #[arg(short, long)]
    suspect: bool,

    /// Show only the N files with the most hits
    #[arg(long)]
    top: Option<usize>,

    /// Machine-readable output
    #[arg(long)]
    json: bool,

    /// Follow symbolic links while walking directories
    #[arg(long)]
    follow_symlinks: bool,

    /// Worker threads (default: all cores)
    #[arg(short = 'j', long)]
    jobs: Option<usize>,

    /// Classify hex instruction words and exit
    #[arg(long, num_args = 1.., value_name = "HEX")]
    decode: Option<Vec<String>>,

    /// Classify hex words read from a file, one per line ("-" = stdin); prints "word extension"
    #[arg(long, value_name = "FILE")]
    decode_file: Option<PathBuf>,
}

struct Hit {
    addr: u64,
    word: u32,
    feat: Feature,
    suspect: bool,
    sym: Option<String>,
}

struct FileResult {
    path: String,
    counts: [u64; NF],
    suspect: [u64; NF],
    hits: Vec<Hit>,
    exact: bool, // mapping symbols were used
}

impl Default for FileResult {
    fn default() -> Self {
        FileResult { path: String::new(), counts: [0; NF], suspect: [0; NF], hits: Vec::new(), exact: false }
    }
}

impl FileResult {
    fn total(&self, shown: &[bool; NF]) -> u64 {
        (0..NF).filter(|&i| shown[i]).map(|i| self.counts[i]).sum()
    }
    fn total_suspect(&self, shown: &[bool; NF]) -> u64 {
        (0..NF).filter(|&i| shown[i]).map(|i| self.suspect[i]).sum()
    }
}

enum Scanned {
    A64(FileResult),
    A32,
    NotElf,
    Error(String, String),
}

fn ascii4(w: u32) -> bool {
    w.to_le_bytes().iter().all(|&b| (0x20..0x7f).contains(&b) || b == 0) && w != 0
}

fn scan_file(path: &Path, display: String, shown: &[bool; NF], want_hits: bool) -> Scanned {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Scanned::Error(display, e.to_string()),
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len < 64 {
        return Scanned::NotElf;
    }
    // SAFETY: read-only mapping; a file truncated underneath us is the caller's problem
    let map = match unsafe { memmap2::Mmap::map(&f) } {
        Ok(m) => m,
        Err(e) => return Scanned::Error(display, e.to_string()),
    };
    if !elf::is_elf(&map) {
        return Scanned::NotElf;
    }
    let Some(p) = elf::parse(&map) else {
        return Scanned::Error(display, "malformed or big-endian ELF".into());
    };
    match p.kind {
        elf::Kind::A64 => {}
        elf::Kind::A32 => return Scanned::A32,
        elf::Kind::Other => return Scanned::NotElf,
    }

    let mut r = FileResult { path: display, exact: !p.mapping.is_empty(), ..Default::default() };
    for range in &p.code {
        let skip = ((4 - (range.addr % 4)) % 4) as usize;
        let Some(bytes) = map.get(range.off + skip..range.off + range.len) else { continue };
        let words: Vec<u32> = bytes.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
        let base = range.addr + skip as u64;
        // Words reachable only by a jump: direct branch/ADR targets and function symbols.
        let mut target = vec![false; words.len()];
        for (i, &w) in words.iter().enumerate() {
            if let Some(t) = branch_target(w, i) {
                if (0..words.len() as i64).contains(&t) {
                    target[t as usize] = true;
                }
            }
        }
        for f in &p.funcs {
            if f.0 >= base && f.0 < base + 4 * words.len() as u64 && (f.0 - base) % 4 == 0 {
                target[((f.0 - base) / 4) as usize] = true;
            }
        }
        // false between an unconditional terminator and the next jump target: literal
        // pools, jump tables, padding and prefix data live there
        let mut reachable = true;
        for (i, &w) in words.iter().enumerate() {
            if target[i] || is_function_entry(w) {
                reachable = true;
            }
            let was_reachable = reachable;
            if is_terminator(w) {
                reachable = false;
            }
            // -fsanitize=function signature + type hash in front of a function: data
            if w == UBSAN_FUNCTION_SIG || (i > 0 && words[i - 1] == UBSAN_FUNCTION_SIG) {
                continue;
            }
            let Some(feat) = classify(w) else { continue };
            let addr = base + 4 * i as u64;
            let suspect = match p.is_data(addr) {
                Some(true) => continue, // mapping symbols: data, not code
                Some(false) => false,
                None => {
                    let prev = i.checked_sub(1).map(|j| words[j]);
                    let next = words.get(i + 1).copied();
                    ascii4(w)
                        || [prev, next].into_iter().flatten().any(|n| looks_like_data_or_trap(n) || ascii4(n))
                        // prefix data (KCFI type hash etc.): after a terminator, right before a function
                        || (prev.is_none_or(is_terminator) && next.is_some_and(is_function_entry))
                        || p.starts_function_within(addr, 8)
                        || !was_reachable
                }
            };
            let fi = feat as usize;
            if suspect {
                r.suspect[fi] += 1;
            } else {
                r.counts[fi] += 1;
            }
            if want_hits && shown[fi] {
                r.hits.push(Hit { addr, word: w, feat, suspect, sym: None });
            }
        }
    }
    for h in &mut r.hits {
        h.sym = p.symbolize(h.addr);
    }
    Scanned::A64(r)
}

fn collect(path: &Path, follow: bool, out: &mut Vec<PathBuf>, errors: &mut Vec<(String, String)>) {
    let md = if follow { std::fs::metadata(path) } else { std::fs::symlink_metadata(path) };
    match md {
        Ok(m) if m.is_dir() => match std::fs::read_dir(path) {
            Ok(rd) => {
                let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
                entries.sort();
                for e in entries {
                    collect(&e, follow, out, errors);
                }
            }
            Err(e) => errors.push((path.display().to_string(), e.to_string())),
        },
        Ok(m) if m.is_file() => out.push(path.to_path_buf()),
        Ok(_) => {} // symlink (not followed), device, socket, ...
        Err(e) => errors.push((path.display().to_string(), e.to_string())),
    }
}

fn parse_version(s: &str) -> Option<(u8, u8)> {
    let s = s.trim_start_matches(['v', 'V']).trim_start_matches("armv").trim_end_matches("-a");
    let (maj, min) = s.split_once('.').unwrap_or((s, "0"));
    let (maj, min): (u8, u8) = (maj.parse().ok()?, min.parse().ok()?);
    match maj {
        8 if min <= 9 => Some((8, min)),
        9 if min <= 6 => Some((8, min + 5)),
        _ => None,
    }
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => write!(o, "\\u{:04x}", c as u32).unwrap(),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn main() -> ExitCode {
    let args = Args::parse();

    if let Some(file) = &args.decode_file {
        use std::io::{BufRead, Write};
        let input: Box<dyn BufRead> = if file.as_os_str() == "-" {
            Box::new(std::io::stdin().lock())
        } else {
            match std::fs::File::open(file) {
                Ok(f) => Box::new(std::io::BufReader::new(f)),
                Err(e) => {
                    eprintln!("a64scan: {}: {e}", file.display());
                    return ExitCode::from(2);
                }
            }
        };
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        for line in input.lines().map_while(Result::ok) {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let Ok(w) = u32::from_str_radix(t.trim_start_matches("0x"), 16) else {
                eprintln!("a64scan: not a hex word: {t}");
                return ExitCode::from(2);
            };
            writeln!(out, "{:08x} {}", w, classify(w).map_or("-", |f| f.name())).ok();
        }
        return ExitCode::SUCCESS;
    }

    if let Some(words) = &args.decode {
        let mut ok = true;
        for s in words {
            match u32::from_str_radix(s.trim_start_matches("0x"), 16) {
                Ok(w) => match classify(w) {
                    Some(f) => println!("{:08x}  {:<10} {:<6} {}", w, f.name(), f.since_str(), f.description()),
                    None => println!("{:08x}  -          armv8.0 (or not recognised)", w),
                },
                Err(_) => {
                    eprintln!("a64scan: not a hex word: {s}");
                    ok = false;
                }
            }
        }
        return if ok { ExitCode::SUCCESS } else { ExitCode::from(2) };
    }

    // ---- which extensions count as unsupported
    let mut allowed: BTreeSet<Feature> = BTreeSet::new();
    let feat_list = |names: &[String]| -> Result<Vec<Feature>, String> {
        names
            .iter()
            .map(|n| n.trim())
            .filter(|n| !n.is_empty() && *n != "none")
            .map(|n| Feature::from_name(n).ok_or_else(|| format!("unknown extension '{n}' (see --help)")))
            .collect()
    };
    let (allow, deny) = match (feat_list(&args.allow), feat_list(&args.deny)) {
        (Ok(a), Ok(d)) => (a, d),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("a64scan: {e}");
            return ExitCode::from(2);
        }
    };
    allowed.extend(allow);
    if let Some(v) = &args.upto {
        let Some(ver) = parse_version(v) else {
            eprintln!("a64scan: bad --upto version '{v}' (use v8.0 .. v8.9 or v9.0 .. v9.6)");
            return ExitCode::from(2);
        };
        allowed.extend(ALL.iter().copied().filter(|f| f.since() <= ver && !f.is_hint()));
    }
    for d in deny {
        allowed.remove(&d);
    }
    let mut shown = [false; NF];
    for f in ALL {
        shown[f as usize] = !allowed.contains(&f) && (args.hints || !f.is_hint());
    }

    if let Some(j) = args.jobs {
        rayon::ThreadPoolBuilder::new().num_threads(j).build_global().ok();
    }

    // ---- walk + scan
    let t0 = Instant::now();
    let mut files = Vec::new();
    let mut walk_errors = Vec::new();
    for p in &args.paths {
        collect(p, args.follow_symlinks, &mut files, &mut walk_errors);
    }
    let want_hits = args.list || args.json;
    let scanned: Vec<Scanned> =
        files.par_iter().map(|p| scan_file(p, p.display().to_string(), &shown, want_hits)).collect();
    let elapsed = t0.elapsed();

    let mut results = Vec::new();
    let (mut n_a32, mut errors) = (0usize, walk_errors);
    for s in scanned {
        match s {
            Scanned::A64(r) => results.push(r),
            Scanned::A32 => n_a32 += 1,
            Scanned::NotElf => {}
            Scanned::Error(p, e) => errors.push((p, e)),
        }
    }
    let n_a64 = results.len();

    let mut totals = [0u64; NF];
    let mut totals_suspect = [0u64; NF];
    let mut files_with = [0usize; NF];
    for r in &results {
        for i in 0..NF {
            totals[i] += r.counts[i];
            totals_suspect[i] += r.suspect[i];
            files_with[i] += (r.counts[i] > 0) as usize;
        }
    }
    let unsupported: u64 = (0..NF).filter(|&i| shown[i] && !ALL[i].is_hint()).map(|i| totals[i]).sum();

    let mut rows: Vec<&FileResult> = results
        .iter()
        .filter(|r| r.total(&shown) > 0 || (args.suspect && r.total_suspect(&shown) > 0))
        .collect();
    rows.sort_by(|a, b| b.total(&shown).cmp(&a.total(&shown)).then(a.path.cmp(&b.path)));
    if let Some(n) = args.top {
        rows.truncate(n);
    }
    let cols: Vec<usize> = (0..NF).filter(|&i| shown[i] && rows.iter().any(|r| r.counts[i] + r.suspect[i] > 0)).collect();

    if args.json {
        let mut o = String::from("{\n");
        let allowed_s: Vec<String> = allowed.iter().map(|f| json_str(f.name())).collect();
        writeln!(o, "  \"allowed\": [{}],", allowed_s.join(", ")).unwrap();
        writeln!(o, "  \"scanned\": {{\"aarch64\": {n_a64}, \"aarch32_skipped\": {n_a32}, \"errors\": {}}},", errors.len()).unwrap();
        o.push_str("  \"files\": [\n");
        for (k, r) in rows.iter().enumerate() {
            let counts: Vec<String> = cols.iter().filter(|&&i| r.counts[i] > 0).map(|&i| format!("{}: {}", json_str(ALL[i].name()), r.counts[i])).collect();
            let susp: Vec<String> = cols.iter().filter(|&&i| r.suspect[i] > 0).map(|&i| format!("{}: {}", json_str(ALL[i].name()), r.suspect[i])).collect();
            let hits: Vec<String> = r
                .hits
                .iter()
                .map(|h| {
                    format!(
                        "{{\"addr\": \"{:#x}\", \"word\": \"{:08x}\", \"ext\": {}, \"suspect\": {}, \"symbol\": {}}}",
                        h.addr,
                        h.word,
                        json_str(h.feat.name()),
                        h.suspect,
                        h.sym.as_deref().map(json_str).unwrap_or("null".into())
                    )
                })
                .collect();
            write!(
                o,
                "    {{\"path\": {}, \"mapping_symbols\": {}, \"counts\": {{{}}}, \"suspect\": {{{}}}, \"hits\": [{}]}}{}\n",
                json_str(&r.path),
                r.exact,
                counts.join(", "),
                susp.join(", "),
                hits.join(", "),
                if k + 1 < rows.len() { "," } else { "" }
            )
            .unwrap();
        }
        o.push_str("  ],\n  \"totals\": {");
        let t: Vec<String> = (0..NF)
            .filter(|&i| shown[i] && totals[i] + totals_suspect[i] > 0)
            .map(|i| format!("{}: {{\"insns\": {}, \"files\": {}, \"suspect\": {}}}", json_str(ALL[i].name()), totals[i], files_with[i], totals_suspect[i]))
            .collect();
        o.push_str(&t.join(", "));
        o.push_str("},\n  \"errors\": [");
        let e: Vec<String> = errors.iter().map(|(p, e)| format!("{{\"path\": {}, \"error\": {}}}", json_str(p), json_str(e))).collect();
        o.push_str(&e.join(", "));
        o.push_str("]\n}");
        println!("{o}");
    } else {
        print_human(&args, &allowed, &rows, &cols, &totals, &totals_suspect, &files_with, &shown);
        eprintln!(
            "a64scan: {} AArch64 ELF files in {:.1}s{}{}",
            n_a64,
            elapsed.as_secs_f64(),
            if n_a32 > 0 { format!(", {n_a32} 32-bit ARM skipped") } else { String::new() },
            if errors.is_empty() { String::new() } else { format!(", {} errors", errors.len()) }
        );
        for (p, e) in errors.iter().take(10) {
            eprintln!("  error: {p}: {e}");
        }
    }

    if !errors.is_empty() && n_a64 == 0 {
        ExitCode::from(2)
    } else if unsupported > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[allow(clippy::too_many_arguments)]
fn print_human(
    args: &Args,
    allowed: &BTreeSet<Feature>,
    rows: &[&FileResult],
    cols: &[usize],
    totals: &[u64; NF],
    totals_suspect: &[u64; NF],
    files_with: &[usize; NF],
    shown: &[bool; NF],
) {
    let allowed_s: Vec<&str> = allowed.iter().map(|f| f.name()).collect();
    println!("target: armv8.0{}{}", if allowed_s.is_empty() { "" } else { " + " }, allowed_s.join(", "));
    if rows.is_empty() {
        println!("no instructions beyond the target found");
        if (0..NF).any(|i| shown[i] && totals_suspect[i] > 0) {
            println!("({} suspect hits that look like data; see --suspect)", (0..NF).filter(|&i| shown[i]).map(|i| totals_suspect[i]).sum::<u64>());
        }
        return;
    }

    let pw = rows.iter().map(|r| r.path.len()).max().unwrap_or(4).clamp(4, 70);
    let mut hdr = format!("{:<pw$}", "FILE");
    for &i in cols {
        write!(hdr, " {:>w$}", ALL[i].name(), w = ALL[i].name().len().max(6)).unwrap();
    }
    hdr.push_str("  suspect");
    println!("\n{hdr}");
    for r in rows {
        let path = if r.path.len() > pw { format!("…{}", &r.path[r.path.len() - pw + 1..]) } else { r.path.clone() };
        let mut line = format!("{path:<pw$}");
        for &i in cols {
            let w = ALL[i].name().len().max(6);
            if r.counts[i] > 0 {
                write!(line, " {:>w$}", r.counts[i]).unwrap();
            } else {
                write!(line, " {:>w$}", "·").unwrap();
            }
        }
        let s = r.total_suspect(shown);
        if s > 0 {
            write!(line, "  {s:>7}").unwrap();
        }
        if r.exact {
            line.push_str("  ($x/$d)");
        }
        println!("{}", line.trim_end());
        if args.list {
            let n = if args.max_list == 0 { usize::MAX } else { args.max_list };
            for h in r.hits.iter().filter(|h| args.suspect || !h.suspect).take(n) {
                println!(
                    "    {:#010x}  {:08x}  {:<10} {}{}",
                    h.addr,
                    h.word,
                    h.feat.name(),
                    h.sym.as_deref().unwrap_or("?"),
                    if h.suspect { "  [suspect]" } else { "" }
                );
            }
            let more = r.hits.iter().filter(|h| args.suspect || !h.suspect).count().saturating_sub(n);
            if more > 0 {
                println!("    ... {more} more");
            }
        }
    }

    println!("\n{:<11} {:<6} {:>9} {:>6} {:>8}  description", "EXTENSION", "SINCE", "INSNS", "FILES", "SUSPECT");
    for i in 0..NF {
        if shown[i] && totals[i] + totals_suspect[i] > 0 {
            let f = ALL[i];
            println!("{:<11} {:<6} {:>9} {:>6} {:>8}  {}", f.name(), f.since_str(), totals[i], files_with[i], totals_suspect[i], f.description());
        }
    }
    if allowed.iter().any(|f| f.since() == (8, 0)) || shown.iter().any(|&s| s) {
        println!("(* optional in ARMv8.0)");
    }
}
