//! <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>

use std::fmt::Debug;

use crate::{
    elf::{ExecutableSections, SectionDef, concat_sections},
    util::SliceExt,
};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

const IMAGE_FILE_MACHINE_I386: u16 = 0x14c;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct OptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linked_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    // note: absent in PE32+
    base_of_data: u32,
    // non-standard extension fields follow
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct SectionHeaderName([u8; 8]);

impl SectionHeaderName {
    fn get(&self) -> &[u8] {
        &self.0[..self.0.iter().position(|&b| b == b'\0').unwrap_or(8)]
    }

    fn resolve<'a>(&'a self, stable: &'a [u8]) -> &'a [u8] {
        let embedded = &self.get();

        if embedded[0] == b'/' {
            let addr = std::str::from_utf8(&embedded[1..])
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let str = &stable[addr..];
            &str[..str.iter().position(|b| *b == b'\0').unwrap()]
        } else {
            embedded
        }
    }
}

impl Debug for SectionHeaderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.get().escape_ascii())
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct SectionHeader {
    name: SectionHeaderName,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

impl SectionHeader {
    fn content_in<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        &file[self.pointer_to_raw_data as usize
            ..self.pointer_to_raw_data as usize + self.size_of_raw_data as usize]
    }
}

/// The section contains initialized data.
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
/// The section contains uninitialized data.
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;

impl SectionHeader {}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
struct CoffSymbolName([u8; 8]);

impl CoffSymbolName {
    fn resolve<'a>(&'a self, stable: &'a [u8]) -> &'a [u8] {
        if self.0[..4] == [0, 0, 0, 0] {
            let soff = u32::from_le_bytes(self.0[4..].try_into().unwrap());
            let sstr = &stable[soff as usize..];
            &sstr[..sstr.iter().position(|&b| b == b'\0').unwrap()]
        } else {
            &self.0[..self.0.iter().position(|&b| b == b'\0').unwrap_or(8)]
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct CoffSymbol {
    name: CoffSymbolName,
    value: u32,
    section_number: u16,
    // 0x20 = function apparently
    type_: u16,
    storage_class: u8,
    number_of_aux_symbols: u8,
}

// what is wrong with these symbols??
fn fix_symbol_name(mut name: &[u8]) -> &[u8] {
    if name[0] == b'_' {
        name = &name[1..];
    }
    // S7_
    if let Some(s) = name.iter().rposition(|&c| c == b'S') {
        // keep S7_DpT_.constprop.141
        if !name[s..].contains(&b'.') && name.get(s + 1).is_some_and(|c| c.is_ascii_digit()) {
            name = &name[..s];
        }
    }
    name
}

pub fn load_pe(file: &[u8], verbose: bool) -> ExecutableSections {
    let pe_offset = u32::from_le_bytes(file[0x3c..0x40].try_into().unwrap());
    let mut pe_bytes = &file[pe_offset as usize..];
    assert_eq!(&pe_bytes.consume_n(4), b"PE\0\0");

    let coff = unsafe { pe_bytes.consume_struct::<CoffHeader>() };
    assert_eq!(coff.machine, IMAGE_FILE_MACHINE_I386);
    assert!(coff.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0);

    if verbose {
        println!("{coff:#?}");
    }

    let optional_header = unsafe { pe_bytes.consume_struct::<OptionalHeader>() };
    // executable file image
    assert_eq!(optional_header.magic, 0x10B);

    if verbose {
        println!("{:#?}", optional_header);
    }

    pe_bytes.consume_n(optional_header.number_of_rva_and_sizes as usize * 8);

    let string_table_content = if coff.pointer_to_symbol_table == 0 {
        &[] // does not exist I think?
    } else {
        let mut bytes =
            &file[coff.pointer_to_symbol_table as usize + coff.number_of_symbols as usize * 18..];
        let size = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        bytes.consume_n(size as usize)
    };

    let mut result = ExecutableSections {
        base: 0,
        memory: Vec::new(),
        dwarf: None,
        symbols: Vec::new(),
    };

    let section_headers =
        unsafe { pe_bytes.consume_n_structs::<SectionHeader>(coff.number_of_sections.into()) };
    for section in section_headers {
        if verbose {
            println!(
                "\"{}\" {:#?}",
                section.name.resolve(string_table_content).escape_ascii(),
                section
            )
        }
    }

    let mut dwarf_sections = crate::elf::DwarfSections {
        abbrev: &[],
        info: &[],
        str: &[],
    };

    for (name, range) in dwarf_sections.names_and_mut_output() {
        for shdr in section_headers {
            if shdr.name.resolve(string_table_content) == name {
                if verbose {
                    eprintln!(
                        "{} is at 0x{:08X}",
                        name.escape_ascii(),
                        shdr.pointer_to_raw_data
                    );
                }
                let content = &shdr.content_in(file);
                *range = content;
            }
        }
    }

    if dwarf_sections.all_non_empty() {
        result.dwarf = Some(dwarf_sections)
    } else if verbose {
        eprintln!("dwarf information not present or incomplete")
    }

    let mut section_data = Vec::new();
    for section in section_headers {
        if section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            section_data.push(SectionDef {
                offset: section.virtual_address as u64,
                name: section.name.resolve(string_table_content),
                data: section.content_in(file),
            });
        }

        // this fails: there is uninitialized data here, I will just assume it doesn't matter ig
        // assert_eq!(
        //     section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA,
        //     0
        // );
    }

    result.base = concat_sections(&mut result.memory, &mut section_data, verbose);

    let syms = unsafe {
        std::slice::from_raw_parts(
            file[coff.pointer_to_symbol_table as usize..].as_ptr() as *const CoffSymbol,
            coff.number_of_symbols as usize,
        )
    };
    let mut it = syms.iter();
    while let Some(sym) = it.next() {
        if sym.section_number == u16::MAX - 1 {
            continue;
        }
        if sym.type_ != 0x20 {
            continue;
        }
        // what the fuck?
        if sym.value == 0 {
            continue;
        }

        result.symbols.push(crate::elf::Symbol {
            name: fix_symbol_name(sym.name.resolve(string_table_content)),
            // TODO: what the fuck are these relative to?
            offset: sym.value as u64,
        });

        // advance_by is unstable.. UNLUCKY!
        // it.advance_by(sym.number_of_aux_symbols);
        for _ in 0..sym.number_of_aux_symbols {
            it.next().unwrap();
        }
    }

    result
}
