#![feature(get_many_mut)]

use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Write},
    num::NonZeroUsize,
    ops::Range,
    path::{Path, PathBuf},
    time::Instant,
};

use clap::Parser;
use dwarf::{collect_dwarf_types, parse_dwarf, print_dwarf_tree};
use elf::{load_elf, probe_elf};
use pe::load_pe;
use sig::find_signature_many;

#[path = "aho-corasick.rs"]
mod aho_corasick;
mod arena;
mod dwarf;
mod elf;
mod pe;
mod sig;
mod util;

fn bytes_to_hex(mut output: impl Write, bytes: &[u8]) -> std::fmt::Result {
    const HEX_CHARS: &str = "0123456789abcdef";

    for &b in bytes {
        output.write_char(HEX_CHARS[usize::from(b >> 4)..].chars().next().unwrap())?;
        output.write_char(HEX_CHARS[usize::from(b & 0xF)..].chars().next().unwrap())?;
    }

    Ok(())
}

fn bytes_hex(bytes: &[u8]) -> impl Display {
    struct BytesHex<'a>(&'a [u8]);
    impl Display for BytesHex<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            bytes_to_hex(f, self.0)
        }
    }
    BytesHex(bytes)
}

fn warn(args: std::fmt::Arguments) {
    eprintln!("[\x1b[1;38;5;208m!\x1b[0m] {args}")
}

fn error(args: std::fmt::Arguments) {
    eprintln!("[\x1b[1;38;5;196m-\x1b[0m] {args}")
}

fn plus(args: std::fmt::Arguments) {
    eprintln!("[\x1b[1;38;5;226m*\x1b[0m] {args}");
}

#[macro_export]
macro_rules! warn {
    ($($args: tt)*) => { $crate::warn(format_args!($($args)*)) };
}

#[macro_export]
macro_rules! error {
    ($($args: tt)*) => { $crate::error(format_args!($($args)*)) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureVerify {
    NotFound,
    NonUnique,
    Found(usize),
}

fn verify_unique(bytes: &[u8], signature: &[u8]) -> SignatureVerify {
    let mut it = memchr::memmem::find_iter(bytes, signature);
    let idx = match it.next() {
        Some(idx) => idx,
        None => return SignatureVerify::NotFound,
    };
    match it.next() {
        Some(_) => SignatureVerify::NonUnique,
        None => SignatureVerify::Found(idx),
    }
}

fn path_to_cpp(
    items: &dwarf::Items,
    path: &[dwarf::PathItem],
    output: &mut String,
) -> Result<(), String> {
    for item in path {
        if !output.is_empty() {
            output.push_str("::");
        }

        match item {
            dwarf::PathItem::Namespace(cstr) => output.push_str(cstr.to_str().unwrap()),
            dwarf::PathItem::Structure(type_) => output.push_str(
                items
                    .types
                    .get(type_)
                    .and_then(|x| x.name.as_ref())
                    .map(|x| x.1)
                    .ok_or_else(|| format!("unresolved type structure {type_:?}"))?
                    .to_str()
                    .unwrap(),
            ),
        }
    }

    Ok(())
}

fn type_to_cpp(
    items: &dwarf::Items,
    id: &dwarf::TypeId,
    output: &mut String,
) -> Result<(), String> {
    let type_ = &items
        .types
        .get(id)
        .ok_or_else(|| format!("type {id:?} missing"))?;
    let name: Result<String, String> = type_
        .name
        .as_ref()
        .ok_or_else(|| "type name missing".to_owned())
        .map(|x| {
            let mut output = String::new();
            path_to_cpp(items, &x.0, &mut output).unwrap();
            if !output.is_empty() {
                output.push_str("::");
            }
            output.push_str(x.1.to_str().unwrap());
            output
        });
    match &type_.kind {
        dwarf::TypeKind::Base { .. } | dwarf::TypeKind::Structure(..) | dwarf::TypeKind::Enum => {
            output.push_str(&name?)
        }
        dwarf::TypeKind::Modified { modifier, type_ } => {
            type_to_cpp(items, type_, output)?;
            output.push(' ');
            output.push_str(match modifier {
                dwarf::TypeModifier::Atomic => todo!(),
                dwarf::TypeModifier::Const => "const",
                dwarf::TypeModifier::Immutable => todo!(),
                dwarf::TypeModifier::Packed => todo!(),
                dwarf::TypeModifier::Reference => "&",
                dwarf::TypeModifier::Restrict => todo!(),
                dwarf::TypeModifier::RvalueReference => "&&",
                dwarf::TypeModifier::Shared => todo!(),
                dwarf::TypeModifier::Volatile => "volatile",
            });
        }
        dwarf::TypeKind::Pointer { type_ } => {
            if let Some(id) = type_ {
                type_to_cpp(items, id, output)?;
            } else {
                output.push_str("void");
            }
            output.push('*');
        }
        dwarf::TypeKind::Typedef { type_ } => {
            type_to_cpp(
                items,
                type_
                    .as_ref()
                    .ok_or_else(|| "incomplete typedef".to_owned())?,
                output,
            )?;
        }
        dwarf::TypeKind::Array {
            dimensions,
            element_type,
        } => {
            type_to_cpp(items, element_type, output)?;
            for dimension in dimensions {
                output.push('[');
                if let Some(u) = dimension.upper_bound {
                    write!(output, "{u}").unwrap()
                }
                output.push(']');
            }
        }
        dwarf::TypeKind::Unspecified => todo!(),
    }

    Ok(())
}

fn function_to_cppname(items: &dwarf::Items, function: &dwarf::Function) -> Result<String, String> {
    let mut output = String::new();

    path_to_cpp(items, &function.path, &mut output)?;

    if !output.is_empty() {
        output.push_str("::");
    }

    output.push_str(function.name.to_str().unwrap());

    Ok(output)
}

#[derive(Debug)]
pub struct Function {
    name: String,
    return_type: String,
    parameters: Vec<(String, Option<String>)>,
    ip_start: usize,
}

impl Function {
    fn construct_whole_signature(&self) -> String {
        let mut output = String::new();

        output.push_str(&self.return_type);
        output.push(' ');
        output.push_str(&self.name);
        output.push('(');

        let mut first = true;
        for (type_, name) in &self.parameters {
            if !first {
                output.push_str(", ");
            } else {
                first = false;
            }

            output.push_str(type_);
            if let Some(name) = name {
                output.push(' ');
                output.push_str(name);
            }
        }

        output.push(')');
        output
    }
}

#[derive(Debug)]
struct ZhlFunction {
    start: usize,
    name: String,
}

fn zhl_identify_functions(zhl: &str) -> Vec<ZhlFunction> {
    let mut result = Vec::new();

    let mut ignored_depth = 0;
    for line in zhl.lines() {
        if line.contains("{{") {
            ignored_depth += 1;
            continue;
        } else if line.contains("}}") {
            ignored_depth -= 1;
            continue;
        } else if ignored_depth > 0 {
            continue;
        }

        if line.starts_with("struct") {
            continue;
        }

        let line = &line[..line.find("//").unwrap_or(line.len())];

        if let Some(paren) = line.find('(').filter(|_| !line.starts_with('\"')) {
            // don't support templates anyway
            let name_start = line[..paren].rfind(' ').unwrap();
            let name = line[name_start + 1..paren].to_owned();
            // pointer return type
            let name = name.strip_prefix('*').map(str::to_owned).unwrap_or(name);
            if name.contains('>') {
                error!("{line} ignored: don't understand '>'");
                continue;
            }

            result.push(ZhlFunction {
                start: unsafe { line.as_ptr().offset_from(zhl.as_ptr()) as usize },
                name,
            })
        }
    }

    result
}

struct Replace {
    range: Range<usize>,
    text: String,
}

fn replace_all(text: &mut String, replacements: &mut [Replace]) {
    replacements.sort_unstable_by_key(|k| k.range.start);

    let mut shift = 0;
    for replacement in replacements {
        let start = replacement
            .range
            .start
            .checked_add_signed(shift)
            .expect("possibly overlapping replace");
        let projected = start..replacement.range.end.checked_add_signed(shift).unwrap();
        text.replace_range(projected, &replacement.text);
        shift = shift + replacement.text.len() as isize - replacement.range.len() as isize;
    }
}

fn zhl_write_result(
    zhl: &mut String,
    zhl_fns: &[ZhlFunction],
    fns: &[Function],
    memory: &[u8],
    addresses: &[usize],
    sigs: &[Option<NonZeroUsize>],
) {
    let mut replacements = Vec::new();
    let mut last = usize::MAX;
    for zf in zhl_fns {
        let sig_quote_end = zhl[..zf.start].rfind('\"').unwrap();
        let sig_quote_start = zhl[..sig_quote_end].rfind('\"').unwrap();
        let orig_sig = &zhl[sig_quote_start + 1..sig_quote_end];
        let orig_hex = orig_sig.trim_start_matches(['!', '.']);

        let Some((_, f, addr, new_sig_hex)) = fns
            .iter()
            .enumerate()
            .filter_map(|(i, f)| {
                if zf.name != f.name {
                    return None;
                }

                let addr = addresses[i];
                let siglen = sigs[i].unwrap().get();
                let new_sig_hex = bytes_hex(&memory[addr..addr + siglen]).to_string();
                let score = new_sig_hex
                    .bytes()
                    .zip(orig_hex.bytes())
                    .position(|(a, b)| a != b)
                    .unwrap_or(orig_hex.len().min(new_sig_hex.len()));

                Some((score, f, addr, new_sig_hex))
            })
            .max_by_key(|&(score, ..)| score)
        else {
            error!("{} not found in collected functions", zf.name);
            continue;
        };

        let dot = if last < addr { "." } else { "" };
        let exc = if orig_sig.contains('!') { "!" } else { "" };
        last = addr;

        eprintln!(
            "[0x{addr:08x}] {} {:?} -> \"{exc}{dot}{}\"",
            f.name, orig_sig, new_sig_hex
        );

        if !orig_hex.starts_with(&new_sig_hex[..8.min(orig_hex.len()).min(new_sig_hex.len())]) {
            warn!("suspicious signature: differs in the first 8 characters")
        }

        replacements.push(Replace {
            range: sig_quote_start + 1..sig_quote_end,
            text: format!("{exc}{dot}{}", new_sig_hex),
        });
    }

    replace_all(zhl, &mut replacements);
}

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    verbose: bool,
    binary: PathBuf,
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    DwarfTree,
    DwarfItems,
    Print,
    PrintSyms,
    PopulateZhl(PopulateZhl),
}

#[derive(Parser)]
struct PopulateZhl {
    #[clap(short, long)]
    write: bool,
    zhl_files: Vec<PathBuf>,
}

fn stage<R>(name: &str, timed: bool, fun: impl FnOnce() -> R) -> R {
    eprintln!("[\x1b[1;38;5;226m*\x1b[0m] {name}");
    let start = Instant::now();
    let result = fun();
    let end = Instant::now();
    eprint!("[\x1b[1;38;5;118m+\x1b[0m] {name}: done",);
    if timed {
        eprint!(" in {:.2}ms", (end - start).as_secs_f32() * 1000.);
    }
    eprintln!();
    result
}

fn main() {
    let args = Args::parse();

    let exe = std::fs::read(args.binary).unwrap();
    let sections = if probe_elf(&exe) {
        stage("Loading ELF file", true, || load_elf(&exe, args.verbose))
    } else {
        stage("Loading PE file", true, || load_pe(&exe, args.verbose))
    };

    if let Subcommand::PrintSyms = args.subcommand {
        for sym in sections.symbols {
            println!("[0x{:08x}] {}", sym.offset, sym.name.escape_ascii())
        }

        return;
    }

    let info = stage("Parsing DWARF", true, || {
        parse_dwarf(
            &sections
                .dwarf
                .expect("primary executable doesn't contain DWARF information"),
        )
    });

    if let Subcommand::DwarfTree = args.subcommand {
        print_dwarf_tree(&info);
        return;
    }

    let items = stage("Collecting function and type information", true, || {
        collect_dwarf_types(&info)
    });

    if let Subcommand::DwarfItems = args.subcommand {
        println!("{items:#?}");
        return;
    }

    struct ZhlContext<'a> {
        path: &'a Path,
        text: String,
        fns: Vec<ZhlFunction>,
    }

    // this could be an option or smthn i dont care rn
    let (use_filter, filter_set, zhls) = match &args.subcommand {
        Subcommand::Print => (false, HashSet::new(), Vec::new()),
        Subcommand::PopulateZhl(cmd) => stage("Reading ZHL", false, || {
            let mut filters = HashSet::new();
            let mut zhls = Vec::new();
            for path in &cmd.zhl_files {
                let text = std::fs::read_to_string(path).unwrap();
                let fns = zhl_identify_functions(&text);
                filters.extend(fns.iter().map(|f| f.name.clone()));
                zhls.push(ZhlContext { path, text, fns })
            }

            (true, filters, zhls)
        }),
        _ => unreachable!(),
    };

    let sym_to_addr = sections
        .symbols
        .iter()
        .map(|s| (s.name, s.offset))
        .collect::<HashMap<_, _>>();
    let mut seen_overloads = HashMap::<_, u32>::new();

    let mut functions = Vec::new();
    for fun in &items.functions {
        let cppname = match function_to_cppname(&items, fun) {
            Ok(cppname) => cppname,
            Err(e) => {
                error!("failed to determine full c++ name of {:?}: {e}", fun.name);
                continue;
            }
        };

        if use_filter && !filter_set.contains(&cppname) {
            continue;
        }

        let dwarf_ip = fun
            .ip_range
            .as_ref()
            .filter(|x| x.start != 0)
            .and_then(|x| sections.fn_address_base.map(|b| (x.start - b) as usize));
        let symbol_ip = fun
            .linkage_name
            .and_then(|n| sym_to_addr.get(n.to_bytes()).copied())
            .map(|a| a as usize);

        // eprintln!("{dwarf_ip:?} {symbol_ip:?} {:?}", sections.fn_address_base);

        let Some(ip_start) = symbol_ip.or(dwarf_ip) else {
            if args.verbose {
                eprintln!("failed to determine address for {cppname}()");
            }
            continue;
        };

        if *seen_overloads
            .entry((cppname.clone(), ip_start))
            .and_modify(|x| *x += 1)
            .or_insert(0)
            > 0
        {
            if args.verbose {
                eprintln!(
                    "more than one instance of {cppname:?} encountered (possibly in different compilation units)"
                );
            }
            continue;
        }

        let return_type = match fun.return_type {
            Some(id) => {
                let mut output = String::new();
                match type_to_cpp(&items, &id, &mut output) {
                    Ok(_) => output,
                    Err(e) => {
                        error!("failed to stringify type: {e}");
                        error!("\tin function: {cppname}");
                        continue;
                    }
                }
            }
            None => "void".to_owned(),
        };

        let mut parameters = Vec::new();
        for (i, param) in fun.parameters.iter().enumerate() {
            let name = param.name.map(|c| c.to_str().unwrap().to_owned());
            let type_ = {
                let mut output = String::new();
                match type_to_cpp(&items, &param.type_, &mut output) {
                    Ok(_) => output,
                    Err(e) => {
                        error!("failed to stringify type: {e}");
                        error!("\tin function: {cppname}");
                        if let Some(name) = name.as_ref() {
                            error!("\tin parameter: {name}");
                        } else {
                            error!("\tin parameter: #{}", i + 1);
                        }
                        continue;
                    }
                }
            };

            parameters.push((type_, name));
        }

        if cppname.contains('<') {
            warn!("{cppname:?} contains template arguments: skipping");
        }

        functions.push(Function {
            return_type,
            parameters,
            name: cppname,
            ip_start,
        });
    }

    // doesn't work with populate-zhl because it doesn't change the order
    // in the zhl file
    // functions.sort_unstable_by_key(|f| f.ip_start);
    let addresses = functions.iter().map(|f| f.ip_start).collect::<Vec<_>>();

    let mut signatures = vec![None; addresses.len()];
    stage("Finding signatures", true, || {
        find_signature_many(&sections.memory, &addresses, &mut signatures, true)
    });

    // FIXME: this is no longer correct (prefix_only_if_sorted)
    // for ((fun, &addr), &siglen) in functions
    //     .iter()
    //     .zip(addresses.iter())
    //     .zip(signatures.iter())
    // {
    //     let signature = &sections.memory[addr..addr + siglen.unwrap().get()];
    //     let verify = verify_unique(&sections.memory, signature);
    //     if verify != SignatureVerify::Found(addr) {
    //         panic!("signature validation failed: {verify:?}");
    //     }
    // }

    match args.subcommand {
        Subcommand::Print => {
            for ((fun, &addr), &siglen) in functions
                .iter()
                .zip(addresses.iter())
                .zip(signatures.iter())
            {
                let siglen = siglen.unwrap();
                let signature = &sections.memory[addr..addr + siglen.get()];

                println!(
                    "[0x{addr:08x}] \"{}\" {}",
                    bytes_hex(signature),
                    fun.construct_whole_signature()
                );
            }
        }
        Subcommand::PopulateZhl(ref cmd) => {
            let get_sig = |idx: usize| {
                let siglen = signatures[idx].unwrap();
                &sections.memory[addresses[idx]..addresses[idx] + siglen.get()]
            };

            for mut zhl in zhls {
                stage(&format!("Writing {}", zhl.path.display()), false, || {
                    let mut zf_names = HashSet::new();
                    for zf in &zhl.fns {
                        if zf_names.insert(zf.name.clone()) {
                            let mut first = None;
                            let mut overload_idx = 0;
                            for (fi, f) in functions.iter().enumerate() {
                                if f.name != zf.name {
                                    continue;
                                }

                                if let Some(previous) = first {
                                    if overload_idx == 0 {
                                        warn!("function {} has multiple overloads", zf.name);
                                        overload_idx += 1;
                                        warn!(
                                            "{overload_idx}. [0x{:08x}] \"{}\" {}",
                                            addresses[previous],
                                            bytes_hex(get_sig(previous)),
                                            functions[previous].construct_whole_signature()
                                        );
                                    }

                                    overload_idx += 1;
                                    warn!(
                                        "{overload_idx}. [0x{:08x}] \"{}\" {}",
                                        addresses[fi],
                                        bytes_hex(get_sig(fi)),
                                        functions[fi].construct_whole_signature()
                                    );
                                } else {
                                    first = Some(fi);
                                }
                            }

                            if overload_idx > 0 {
                                warn!(
                                    "make sure the script picked the right one, and correct any renamed overloads in the ZHL file"
                                )
                            }
                        }
                    }

                    zhl_write_result(
                        &mut zhl.text,
                        &zhl.fns,
                        &functions,
                        &sections.memory,
                        &addresses,
                        &signatures,
                    );
                    if cmd.write {
                        std::fs::write(zhl.path, zhl.text).unwrap();
                    } else {
                        print!("{}", zhl.text);
                    }
                });
            }
        }
        _ => unreachable!(),
    }
}
