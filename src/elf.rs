use std::ffi::CStr;

type Elf64Addr = u64;
type Elf64Off = u64;
type Elf64Half = u16;
type Elf64Word = u32;
#[expect(dead_code)]
type Elf64Sword = i32;
type Elf64Xword = u64;
#[expect(dead_code)]
type Elf64Sxword = i64;

#[repr(C, packed)]
struct Elf64Ehdr {
    e_ident: [u8; 16],      /* ELF identification */
    e_type: Elf64Half,      /* Object file type */
    e_machine: Elf64Half,   /* Machine type */
    e_version: Elf64Word,   /* Object file version */
    e_entry: Elf64Addr,     /* Entry point address */
    e_phoff: Elf64Off,      /* Program header offset */
    e_shoff: Elf64Off,      /* Section header offset */
    e_flags: Elf64Word,     /* Processor-specific flags */
    e_ehsize: Elf64Half,    /* ELF header size */
    e_phentsize: Elf64Half, /* Size of program header entry */
    e_phnum: Elf64Half,     /* Number of program header entries */
    e_shentsize: Elf64Half, /* Size of section header entry */
    e_shnum: Elf64Half,     /* Number of section header entries */
    e_shstrndx: Elf64Half,  /* Section name string table index */
}

#[repr(C, packed)]
struct Elf64Shdr {
    sh_name: Elf64Word,       /* Section name */
    sh_type: Elf64Word,       /* Section type */
    sh_flags: Elf64Xword,     /* Section attributes */
    sh_addr: Elf64Addr,       /* Virtual address in memory */
    sh_offset: Elf64Off,      /* Offset in file */
    sh_size: Elf64Xword,      /* Size of section */
    sh_link: Elf64Word,       /* Link to other section */
    sh_info: Elf64Word,       /* Miscellaneous information */
    sh_addralign: Elf64Xword, /* Address alignment boundary */
    sh_entsize: Elf64Xword,   /* Size of entries, if section has table */
}

impl Elf64Shdr {
    unsafe fn content_in<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        unsafe {
            std::slice::from_raw_parts::<'a>(
                file.as_ptr().add(self.sh_offset as usize),
                self.sh_size as usize,
            )
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct Elf64Sym {
    st_name: Elf64Word,
    st_info: u8,
    st_other: u8,
    st_shndx: Elf64Half,
    st_value: Elf64Addr,
    st_size: Elf64Xword,
}

const ELF_MAG: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFOSABI_LINUX: u8 = 3;
const ET_EXEC: Elf64Half = 2;
const SHT_NOBITS: Elf64Xword = 8;

#[derive(Debug, Clone, Copy)]
pub struct DwarfSections<'a> {
    // pub aranges: &'a [u8],
    // pub ranges: &'a [u8],
    pub abbrev: &'a [u8],
    pub info: &'a [u8],
    pub str: &'a [u8],
}

impl<'a> DwarfSections<'a> {
    pub fn names_and_mut_output(&mut self) -> [(&'static [u8], &mut &'a [u8]); 3] {
        [
            // (b".debug_aranges", &mut self.aranges),
            // (b".debug_ranges", &mut self.ranges),
            (b".debug_abbrev", &mut self.abbrev),
            (b".debug_info", &mut self.info),
            (b".debug_str", &mut self.str),
        ]
    }

    pub fn all_non_empty(&self) -> bool {
        !self.abbrev.is_empty() && !self.info.is_empty() && !self.str.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Symbol<'a> {
    pub name: &'a [u8],
    pub offset: u64,
}

pub struct ExecutableSections<'a> {
    pub fn_address_base: Option<u64>,
    pub memory: Vec<u8>,
    pub dwarf: Option<DwarfSections<'a>>,
    pub symbols: Vec<Symbol<'a>>,
}

struct StringTable<'a>(&'a [u8]);

impl<'a> StringTable<'a> {
    pub unsafe fn get(&self, offset: usize) -> &'a CStr {
        unsafe { CStr::from_ptr(self.0.as_ptr().add(offset) as *const i8) }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SectionDef<'a> {
    pub offset: u64,
    pub name: &'a [u8],
    pub data: &'a [u8],
}

pub fn concat_sections(output: &mut Vec<u8>, sections: &mut [SectionDef], verbose: bool) -> u64 {
    sections.sort_unstable_by_key(|&s| s.offset);

    let base = sections[0].offset;
    output.reserve((sections.last().unwrap().offset - base) as usize);

    // this whole thing is like, wrong but it doesn't matter
    for &mut SectionDef { offset, name, data } in sections {
        if verbose {
            eprintln!(
                "0x{offset:08X} \"{}\" {} bytes",
                name.escape_ascii(),
                data.len()
            );
        }

        let from_base = (offset - base) as usize;
        if output.len() < from_base {
            output.resize(from_base, 0x69);
        }

        output.splice(
            from_base..(from_base + data.len()).min(output.len()),
            data.iter().copied(),
        );
    }

    base
}

pub fn probe_elf(file: &[u8]) -> bool {
    file.starts_with(ELF_MAG)
}

pub fn load_elf<'a>(file: &'a [u8], verbose: bool) -> ExecutableSections<'a> {
    let hdr = unsafe { &*(file.as_ptr() as *const Elf64Ehdr) };
    assert_eq!(&hdr.e_ident[..4], ELF_MAG);
    assert_eq!(hdr.e_ident[4], ELFCLASS64);
    assert_eq!(hdr.e_ident[5], ELFDATA2LSB);
    assert_eq!(hdr.e_ident[6], 1); // version
    assert_eq!(hdr.e_ident[7], ELFOSABI_LINUX);
    assert_eq!(hdr.e_ident[8], 0);
    assert_eq!({ hdr.e_type }, ET_EXEC);
    // trust the other fields are correct

    let section_headers = unsafe {
        std::slice::from_raw_parts::<'a, Elf64Shdr>(
            // perform absolutely zero validation, will segfault on invalid files :)
            file.as_ptr().add(hdr.e_shoff as usize) as *const _,
            hdr.e_shnum as usize,
        )
    };

    let shstrtab_shdr = &section_headers[hdr.e_shstrndx as usize];
    let shstrtab = StringTable(
        &file[shstrtab_shdr.sh_offset as usize
            ..(shstrtab_shdr.sh_offset + shstrtab_shdr.sh_size) as usize],
    );

    let strtab_shdr = section_headers
        .iter()
        .find(|h| unsafe { shstrtab.get(h.sh_name as usize) } == c".strtab")
        .unwrap();
    let strtab = StringTable(
        &file[strtab_shdr.sh_offset as usize
            ..(strtab_shdr.sh_offset + strtab_shdr.sh_size) as usize],
    );

    let mut section_data = Vec::new();
    for shdr in section_headers {
        if shdr.sh_type == 0 {
            continue;
        }

        let addr = shdr.sh_addr;
        assert!(shdr.sh_addralign == 0 || addr % shdr.sh_addralign == 0);

        if addr != 0 {
            assert!(shdr.sh_flags & SHT_NOBITS == 0);

            section_data.push(SectionDef {
                offset: addr,
                name: unsafe { shstrtab.get(shdr.sh_name as usize).to_bytes() },
                data: unsafe { shdr.content_in(file) },
            });
        }
    }

    let mut memory = Vec::new();
    let base = concat_sections(&mut memory, &mut section_data, verbose);

    let mut dwarf_sections = DwarfSections {
        // aranges: &[],
        // ranges: &[],
        abbrev: &[],
        info: &[],
        str: &[],
    };

    for (name, range) in dwarf_sections.names_and_mut_output() {
        for shdr in section_headers {
            if unsafe { shstrtab.get(shdr.sh_name as usize) }.to_bytes() == name {
                if verbose {
                    eprintln!("{} is at 0x{:08X}", name.escape_ascii(), { shdr.sh_offset });
                }
                let content = unsafe { shdr.content_in(file) };
                *range = content;
            }
        }
    }

    let code_index = section_headers
        .iter()
        .position(|s| unsafe { shstrtab.get(s.sh_name as usize) } == c".text")
        .unwrap();
    let mut symbols = Vec::new();

    for shdr in section_headers {
        if unsafe { shstrtab.get(shdr.sh_name as usize) } == c".symtab" {
            if verbose {
                eprintln!("symbol table is at 0x{:08X}", { shdr.sh_offset });
            }
            let content = unsafe { shdr.content_in(file) };
            let syms = unsafe {
                std::slice::from_raw_parts(
                    content.as_ptr() as *const Elf64Sym,
                    content.len() / std::mem::size_of::<Elf64Sym>(),
                )
            };

            for sym in syms {
                let name = unsafe { strtab.get(sym.st_name as usize) };
                if sym.st_shndx as usize == code_index {
                    symbols.push(Symbol {
                        name: name.to_bytes(),
                        offset: sym.st_value - base,
                    });
                }
            }
        }
    }

    ExecutableSections {
        // TODO:
        fn_address_base: None,
        memory,
        dwarf: Some(dwarf_sections),
        symbols,
    }
}
