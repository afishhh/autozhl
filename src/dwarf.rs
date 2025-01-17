#![allow(dead_code)]

use std::{collections::HashMap, ffi::CStr, fmt::Debug, ops::Range};

use crate::{elf::DwarfSections, util::SliceExt, warn};

type MutBytes<'a, 'b> = &'a mut &'b [u8];

pub fn uleb128(input: MutBytes) -> u64 {
    let mut result = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = input.consume_first();
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return result;
        }
        shift += 7;
    }
}

pub fn sleb128(input: MutBytes) -> i64 {
    let mut result = 0;
    let mut shift: u32 = 0;
    let mut byte;
    loop {
        byte = input.consume_first();
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        /* sign bit of byte is second high order bit (0 x40 ) */
        if byte & 0x80 == 0 {
            break;
        }
    }
    if shift < i64::BITS && byte & 0x40 != 0 {
        /* sign extend */
        result |= -(1 << shift);
    }

    result
}

mod ops;

#[derive(Debug, Clone, Copy)]
struct CompilationUnit {
    dwarf64: bool,
    base: *const u8,
    version: u16,
    debug_abbrev_offset: usize,
    address_size: u8,
}

impl CompilationUnit {
    fn address64(&self) -> bool {
        match self.address_size {
            8 => true,
            4 => false,
            sz => panic!("unsupported compilation unit address size: {sz}"),
        }
    }
}

fn iter_compilation_units(mut info: &[u8]) -> impl Iterator<Item = (CompilationUnit, &[u8])> {
    std::iter::from_fn(move || {
        if info.is_empty() {
            return None;
        }

        let base = info.as_ptr();

        let (is64, length) = {
            let small = info.consume_u32_le();
            if small == 0xFFFFFFFF {
                (true, info.consume_u64_le() as usize)
            } else {
                (false, small as usize)
            }
        };

        let mut content = &info[..length];
        info = &info[length..];
        if content.is_empty() {
            // what the fuck?
            return None;
        }
        let version = content.consume_u16_le();
        let debug_abbrev_offset = content.consume_u32_or_u64_address_le(is64);

        let unit = CompilationUnit {
            dwarf64: is64,
            version,
            debug_abbrev_offset,
            address_size: content.consume_first(),
            base,
        };

        Some((unit, content))
    })
}

#[derive(Debug, Clone)]
struct Abbreviation {
    code: u64,
    tag: ops::DW_TAG,
    children: bool,
    attributes: Vec<(ops::DW_AT, ops::DW_FORM)>,
}

struct AbbrevTable(HashMap<u64, Abbreviation>);

impl AbbrevTable {
    pub fn parse(mut data: &[u8]) -> Self {
        let mut result = Self(HashMap::new());

        loop {
            let code = uleb128(&mut data);
            if code == 0 {
                break;
            }

            let tag = ops::DW_TAG::take(&mut data);
            let children = match data.consume_first() {
                // DW_CHILDREN_yes
                0x01 => true,
                // DW_CHILDREN_no
                0x00 => false,
                v => panic!("invalid abbreviation children value 0x{v:X}"),
            };

            let mut abbrv = Abbreviation {
                code,
                tag,
                children,
                attributes: Vec::new(),
            };

            // println!("ABBRV {code} {tag:?} children={children}");

            loop {
                let at_name = uleb128(&mut data);
                let at_form = uleb128(&mut data);
                if at_name == 0 && at_form == 0 {
                    break;
                }

                // println!(
                //     "\tATTRIBUTE name={:?} (0x{at_name:02X}) form={:?} (0x{at_form:02X})",
                //     ops::DW_AT::from_value(at_name),
                //     ops::DW_FORM::from_value(at_form)
                // );
                abbrv.attributes.push((
                    ops::DW_AT::from_value(at_name).unwrap(),
                    ops::DW_FORM::from_value(at_form).unwrap(),
                ));
            }

            result.0.insert(code, abbrv);
        }

        result
    }
}

#[derive(Clone, Copy)]
struct Expression<'a> {
    content: &'a [u8],
}

impl<'a> Expression<'a> {
    fn iter_ops(&self) -> impl Iterator<Item = Result<ops::DW_OP, u8>> + 'a {
        let mut content = self.content;
        std::iter::from_fn(move || {
            if content.is_empty() {
                return None;
            }

            if let Some(op) = ops::DW_OP::try_take(&mut content) {
                Some(Ok(op))
            } else {
                let opcode = content[0];
                content = &[];
                Some(Err(opcode))
            }
        })
    }

    fn consume(input: MutBytes<'_, 'a>) -> Self {
        let length = uleb128(input);
        let content = input.consume_n(length as usize);

        Self { content }
    }
}

impl Debug for Expression<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for op in self.iter_ops() {
            match op {
                Ok(op) => list.entry(&op),
                Err(opcode) => {
                    struct UnsupportedOp(u8);
                    impl Debug for UnsupportedOp {
                        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            write!(f, "<unsupported opcode: 0x{:X?}>", self.0)
                        }
                    }
                    list.entry(&UnsupportedOp(opcode));
                    break;
                }
            };
        }
        list.finish()
    }
}

#[derive(Debug, Clone, Copy)]
enum AttrValue<'a> {
    Address(usize),
    Bytes(&'a [u8]),
    Signed(i64),
    Expression(Expression<'a>),
    String(&'a CStr),
    EntryIndex(usize),
    RangesOffset(usize),
    LineOffset(usize),
    LocListOffset(usize),
    Flag(bool),
}

impl<'a> AttrValue<'a> {
    fn as_string(&self) -> &'a CStr {
        match self {
            AttrValue::String(cstr) => cstr,
            _ => panic!("not a string: {self:?}"),
        }
    }

    fn as_entry_index(&self) -> usize {
        match self {
            &AttrValue::EntryIndex(index) => index,
            _ => panic!("not an entry index: {self:?}"),
        }
    }

    fn as_flag(&self) -> bool {
        match self {
            &AttrValue::Flag(value) => value,
            _ => panic!("not a flag: {self:?}"),
        }
    }

    fn as_address(&self) -> u64 {
        match *self {
            AttrValue::Address(value) => value as u64,
            _ => panic!("not an unsigned integer: {self:?}"),
        }
    }

    fn as_unsigned(&self) -> u64 {
        match *self {
            AttrValue::Bytes(mut value) if value.len() == 1 => value.consume_first() as u64,
            AttrValue::Bytes(mut value) if value.len() == 2 => value.consume_u16_le() as u64,
            AttrValue::Bytes(mut value) if value.len() == 4 => value.consume_u32_le() as u64,
            AttrValue::Bytes(mut value) if value.len() == 8 => value.consume_u64_le(),
            _ => panic!("not an unsigned integer: {self:?}"),
        }
    }

    fn as_offset_or_address(&self, base: u64) -> u64 {
        match *self {
            AttrValue::Address(value) => value as u64,
            _ => base + self.as_unsigned(),
        }
    }
}

enum SecOffsetPtrClass {
    Line,
    LocList,
    Macro,
    RangeList,
}

impl SecOffsetPtrClass {
    fn for_name(name: ops::DW_AT) -> Self {
        use ops::DW_AT::*;
        match name {
            DW_AT_stmt_list => Self::Line,
            DW_AT_ranges => Self::RangeList,
            DW_AT_location => Self::LocList,
            DW_AT_string_length => Self::LocList,
            DW_AT_data_member_location => Self::LocList,
            DW_AT_frame_base => Self::LocList,
            DW_AT_macro_info => Self::Macro,
            DW_AT_segment => Self::LocList,
            DW_AT_static_link => Self::LocList,
            DW_AT_use_location => Self::LocList,
            DW_AT_vtable_elem_location => Self::LocList,
            at => panic!("sec_offset unsupported for {at:?}"),
        }
    }
}

fn consume_attr_value<'a>(
    cu: &CompilationUnit,
    content: MutBytes<'_, 'a>,
    name: ops::DW_AT,
    form: ops::DW_FORM,
    sections: &DwarfSections<'a>,
) -> AttrValue<'a> {
    match form {
        ops::DW_FORM::DW_FORM_addr => {
            AttrValue::Address(content.consume_u32_or_u64_address_le(cu.address64()))
        }
        ops::DW_FORM::DW_FORM_block1 => {
            let n = content.consume_first().into();
            AttrValue::Bytes(content.consume_n(n))
        }
        ops::DW_FORM::DW_FORM_block2 => {
            let n = content.consume_u16_le().into();
            AttrValue::Bytes(content.consume_n(n))
        }
        ops::DW_FORM::DW_FORM_block4 => todo!(),
        ops::DW_FORM::DW_FORM_data1 => AttrValue::Bytes(content.consume_chunk::<1>()),
        ops::DW_FORM::DW_FORM_data2 => AttrValue::Bytes(content.consume_chunk::<2>()),
        ops::DW_FORM::DW_FORM_data4 => AttrValue::Bytes(content.consume_chunk::<4>()),
        ops::DW_FORM::DW_FORM_data8 => AttrValue::Bytes(content.consume_chunk::<8>()),
        ops::DW_FORM::DW_FORM_string => {
            let end = content.iter().position(|&c| c == b'\0').unwrap() + 1;
            let cstr = CStr::from_bytes_with_nul(&content[..end]).unwrap();
            content.consume_n(end);
            AttrValue::String(cstr)
        }
        ops::DW_FORM::DW_FORM_block => todo!(),
        ops::DW_FORM::DW_FORM_flag => todo!(),
        ops::DW_FORM::DW_FORM_sdata => AttrValue::Signed(sleb128(content)),
        ops::DW_FORM::DW_FORM_strp => AttrValue::String(unsafe {
            CStr::from_ptr(
                sections
                    .str
                    .as_ptr()
                    .add(content.consume_u32_or_u64_address_le(cu.dwarf64))
                    as *const i8,
            )
        }),
        ops::DW_FORM::DW_FORM_udata => todo!(),
        ops::DW_FORM::DW_FORM_ref_addr => todo!(),
        ops::DW_FORM::DW_FORM_ref1 => AttrValue::EntryIndex(content.consume_first().into()),
        ops::DW_FORM::DW_FORM_ref2 => AttrValue::EntryIndex(content.consume_u16_le().into()),
        ops::DW_FORM::DW_FORM_ref4 => AttrValue::EntryIndex(content.consume_u32_le() as usize),
        ops::DW_FORM::DW_FORM_ref8 => AttrValue::EntryIndex(content.consume_u64_le() as usize),
        ops::DW_FORM::DW_FORM_ref_udata => todo!(),
        ops::DW_FORM::DW_FORM_indirect => todo!(),
        ops::DW_FORM::DW_FORM_sec_offset => match SecOffsetPtrClass::for_name(name) {
            SecOffsetPtrClass::Line => {
                AttrValue::LineOffset(content.consume_u32_or_u64_address_le(cu.dwarf64))
            }
            SecOffsetPtrClass::LocList => {
                AttrValue::LocListOffset(content.consume_u32_or_u64_address_le(cu.dwarf64))
            }
            SecOffsetPtrClass::Macro => todo!(),
            SecOffsetPtrClass::RangeList => {
                AttrValue::RangesOffset(content.consume_u32_or_u64_address_le(cu.dwarf64))
            }
        },
        ops::DW_FORM::DW_FORM_exprloc => AttrValue::Expression(Expression::consume(content)),
        ops::DW_FORM::DW_FORM_flag_present => AttrValue::Flag(true),
        ops::DW_FORM::DW_FORM_ref_sig8 => todo!(),
    }
}

#[derive(Debug)]
struct DebuggingInformationEntry<'a> {
    abbreviation_code: u64,
    tag: ops::DW_TAG,
    children: bool,
    attributes: Vec<(ops::DW_AT, AttrValue<'a>)>,
}

impl<'a> DebuggingInformationEntry<'a> {
    fn find_attribute(&self, name: ops::DW_AT) -> Option<&AttrValue<'a>> {
        self.attributes
            .iter()
            .find(|&&(key, _)| key == name)
            .map(|(_, value)| value)
    }

    fn is_incomplete(&self) -> bool {
        self.find_attribute(ops::DW_AT::DW_AT_declaration)
            .is_some_and(|v| v.as_flag())
    }

    fn specified_index(&self) -> Option<usize> {
        self.find_attribute(ops::DW_AT::DW_AT_specification)
            .map(|v| v.as_entry_index())
    }
}

pub struct DwarfInfo<'a> {
    // theoretically copying everything is not necessary and instead
    // I could just make walking the thing easier
    // it could end up being slower though, I don't know
    units: Vec<(
        CompilationUnit,
        AbbrevTable,
        Vec<DebuggingInformationEntry<'a>>,
    )>,
}

pub fn parse_dwarf<'a>(sections: &DwarfSections<'a>) -> DwarfInfo<'a> {
    let mut info = DwarfInfo { units: Vec::new() };

    for (cu, mut content) in iter_compilation_units(sections.info) {
        if cu.version != 4 {
            warn!(
                "ignoring DWARF v{} compilation unit at 0x{:08x}",
                cu.version,
                unsafe { cu.base.offset_from(sections.info.as_ptr()) }
            )
        }

        // println!();
        let abbrevs = AbbrevTable::parse(&sections.abbrev[cu.debug_abbrev_offset..]);

        // println!("{cu:#?}");
        // println!("{} abbreviations loaded", abbrevs.0.len());

        let mut entries = Vec::new();
        let mut offset_to_index = HashMap::new();
        while !content.is_empty() {
            let start = content.as_ptr();
            let abbreviation_code = uleb128(&mut content);
            if abbreviation_code == 0 {
                entries.push(DebuggingInformationEntry {
                    tag: ops::DW_TAG::DW_TAG_user(u64::MAX),
                    children: false,
                    abbreviation_code: 0,
                    attributes: Vec::new(),
                });
                continue;
            }

            let offset = unsafe { start.offset_from(cu.base) as usize };
            offset_to_index.insert(offset, entries.len());

            let abbrv = &abbrevs.0[&abbreviation_code];
            let mut result = DebuggingInformationEntry {
                tag: abbrv.tag,
                children: abbrv.children,
                abbreviation_code,
                attributes: Vec::new(),
            };

            // println!(
            //     "<{offset:X}> ENTRY {:?} children={}",
            //     abbrv.tag, abbrv.children
            // );

            for (name, form) in abbrv.attributes.iter().copied() {
                let data = consume_attr_value(&cu, &mut content, name, form, sections);
                // println!("\t{name:?} = {data:?}");
                result.attributes.push((name, data))
            }

            entries.push(result);
        }

        for entry in entries.iter_mut() {
            for (_, value) in entry.attributes.iter_mut() {
                if let AttrValue::EntryIndex(offset) = value {
                    *offset = offset_to_index[offset];
                }
            }
        }

        info.units.push((cu, abbrevs, entries));
    }

    info
}

pub fn print_dwarf_tree(info: &DwarfInfo) {
    for (_, abbrevs, entries) in info.units.iter() {
        let mut parents: Vec<&DebuggingInformationEntry> = Vec::new();

        for entry in entries.iter() {
            if entry.abbreviation_code == 0 {
                parents.pop();
                continue;
            }

            'skip: {
                if parents.len() > 1 {
                    for parent in parents.iter() {
                        let parent_tag = abbrevs.0[&parent.abbreviation_code].tag;
                        if parent_tag == ops::DW_TAG::DW_TAG_namespace
                            || parent_tag == ops::DW_TAG::DW_TAG_class_type
                        {
                            if let Some(name) = parent.find_attribute(ops::DW_AT::DW_AT_name) {
                                let name = name.as_string();
                                if name.to_bytes() == b"std"
                                    || name.to_str().is_ok_and(|s| s.contains("gnu_cxx"))
                                    || parent
                                        .find_attribute(ops::DW_AT::DW_AT_declaration)
                                        .is_some()
                                {
                                    break 'skip;
                                }
                            }
                        }
                    }
                }

                for _ in 0..parents.len() {
                    print!("\t");
                }

                println!("{:?}", entry.tag);

                for _ in 0..parents.len() + 1 {
                    print!("\t");
                }

                println!("{:?}", entry.attributes);

                for _ in 0..parents.len() + 1 {
                    print!("\t");
                }

                println!("{:?}", parents.iter().map(|x| x.tag).collect::<Vec<_>>());
            }

            if entry.children {
                parents.push(entry);
            }
        }
        assert!(parents.is_empty());
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PathItem<'a> {
    Namespace(&'a CStr),
    Structure(TypeId),
}

#[derive(Debug)]
pub struct Function<'a> {
    pub path: Vec<PathItem<'a>>,
    pub name: &'a CStr,
    pub linkage_name: Option<&'a CStr>,
    pub callconv: Option<ops::DW_CC>,
    // this doesn't actually seem to be set to true literally anywhere
    pub noreturn: bool,
    pub parameters: Vec<Parameter<'a>>,
    pub return_type: Option<TypeId>,
    pub ip_range: Option<Range<u64>>,
}

#[derive(Debug)]
pub struct Parameter<'a> {
    pub name: Option<&'a CStr>,
    pub type_: TypeId,
    pub artificial: bool,
}

#[derive(Debug)]
pub enum TypeModifier {
    Atomic,
    Const,
    Immutable,
    Packed,
    Reference,
    Restrict,
    RvalueReference,
    Shared,
    Volatile,
}

impl TypeModifier {
    fn from_tag(tag: ops::DW_TAG) -> Option<Self> {
        Some(match tag {
            ops::DW_TAG::DW_TAG_atomic_type => TypeModifier::Atomic,
            ops::DW_TAG::DW_TAG_const_type => TypeModifier::Const,
            ops::DW_TAG::DW_TAG_immutable_type => TypeModifier::Immutable,
            ops::DW_TAG::DW_TAG_packed_type => TypeModifier::Packed,
            ops::DW_TAG::DW_TAG_reference_type => TypeModifier::Reference,
            ops::DW_TAG::DW_TAG_rvalue_reference_type => TypeModifier::RvalueReference,
            ops::DW_TAG::DW_TAG_restrict_type => TypeModifier::Restrict,
            ops::DW_TAG::DW_TAG_shared_type => TypeModifier::Shared,
            ops::DW_TAG::DW_TAG_volatile_type => TypeModifier::Volatile,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub enum TypeKind {
    Base {
        encoding: ops::DW_ATE,
        width: u32,
    },
    Modified {
        modifier: TypeModifier,
        type_: TypeId,
    },
    Pointer {
        type_: Option<TypeId>,
    },
    Typedef {
        type_: Option<TypeId>,
    },
    Array {
        dimensions: Vec<ArrayDimension>,
        element_type: TypeId,
    },
    Structure(StructureType),
    Enum,
    Unspecified,
}

#[derive(Debug, Clone, Copy)]
pub struct ArrayDimension {
    pub base_type: Option<TypeId>,
    pub lower_bound: Option<u64>,
    pub upper_bound: Option<u64>,
}

#[derive(Debug)]
pub struct StructureType {
    pub class: bool,
    pub anonymous: bool,
    // not currently populated
    pub members: Vec<Member>,
}

#[derive(Debug)]
pub enum Member {
    Function(FunctionMember),
    Data(DataMember),
}

#[derive(Debug)]
pub struct DataMember {
    pub mutable: bool,
    pub accessibility: Option<ops::DW_ACCESS>,
    pub type_: TypeId,
}

// "Class Variable"
#[derive(Debug)]
pub struct StaticDataMember {
    pub accessibility: Option<ops::DW_ACCESS>,
    pub type_: TypeId,
}

#[derive(Debug)]
pub struct FunctionMember {
    pub function_index: usize,
}

#[derive(Debug)]
pub struct Type<'a> {
    pub name: Option<(Vec<PathItem<'a>>, &'a CStr)>,
    pub incomplete: bool,
    pub kind: TypeKind,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TypeId {
    cu: u32,
    index: u32,
}

struct EntryChildrenIterator<'a> {
    next: Option<&'a DebuggingInformationEntry<'a>>,
    entries: &'a [DebuggingInformationEntry<'a>],
}

impl<'a> EntryChildrenIterator<'a> {
    fn new(index: usize, entries: &'a [DebuggingInformationEntry<'a>]) -> Self {
        if !entries[index].children {
            Self {
                next: None,
                entries,
            }
        } else {
            Self {
                next: Some(&entries[index + 1]),
                entries,
            }
        }
    }
}

impl<'a> Iterator for EntryChildrenIterator<'a> {
    type Item = &'a DebuggingInformationEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next {
            Some(entry) if entry.abbreviation_code == 0 => {
                self.next = None;
                None
            }
            Some(entry) => {
                self.next = entry
                    .find_attribute(ops::DW_AT::DW_AT_sibling)
                    .map(|v| &self.entries[v.as_entry_index()]);
                Some(entry)
            }
            None => None,
        }
    }
}

#[derive(Debug)]
pub struct Items<'a> {
    pub types: HashMap<TypeId, Type<'a>>,
    pub functions: Vec<Function<'a>>,
}

pub fn collect_dwarf_types<'a>(info: &DwarfInfo<'a>) -> Items<'a> {
    let mut items = Items {
        types: HashMap::new(),
        functions: Vec::new(),
    };

    for (cuidx, (_, _, entries)) in info.units.iter().enumerate() {
        struct Parent<'a> {
            idx: usize,
            is_part_of_path: bool,
            entry: &'a DebuggingInformationEntry<'a>,
            function_index: Option<usize>,
        }

        let mut parents: Vec<Parent> = Vec::new();
        let mut path = Vec::new();
        let mut incomplete_functions = HashMap::new();

        for (ei, entry) in entries.iter().enumerate() {
            if entry.abbreviation_code == 0 {
                if parents.pop().unwrap().is_part_of_path {
                    path.pop().unwrap();
                }

                continue;
            }

            let mk_ty_id = |index: usize| TypeId {
                cu: cuidx as u32,
                index: index as u32,
            };

            let mut function_index = None;
            'function: {
                if entry.tag == ops::DW_TAG::DW_TAG_subprogram {
                    if path
                .iter()
                .any(|p| matches!(p, PathItem::Namespace(ns) if [&b"std"[..], b"__gnu_cxx"].contains(&ns.to_bytes())))
            {
                break 'function;
            }

                    if let Some(name) = entry.find_attribute(ops::DW_AT::DW_AT_name) {
                        let name = name.as_string();

                        let initial = Function {
                            path: path.clone(),
                            callconv: entry
                                .find_attribute(ops::DW_AT::DW_AT_calling_convention)
                                .map(|x| ops::DW_CC::from_value(x.as_unsigned()).unwrap()),
                            name,
                            linkage_name: entry
                                .find_attribute(ops::DW_AT::DW_AT_linkage_name)
                                .map(|x| x.as_string()),
                            noreturn: entry
                                .find_attribute(ops::DW_AT::DW_AT_noreturn)
                                .map(|x| x.as_flag())
                                .unwrap_or(false),
                            parameters: Vec::new(),
                            return_type: entry
                                .find_attribute(ops::DW_AT::DW_AT_type)
                                .map(|v| mk_ty_id(v.as_entry_index())),
                            ip_range: None,
                        };

                        if entry.is_incomplete() {
                            incomplete_functions.insert(ei, initial);
                        } else {
                            if !entry.is_incomplete() && entry.children {
                                function_index = Some(items.functions.len());
                            }

                            items.functions.push(initial);
                        }
                    }

                    if let Some(specified) = entry.specified_index() {
                        if let Some(mut fun) = incomplete_functions.remove(&specified) {
                            if let Some(low_pc) = entry
                                .find_attribute(ops::DW_AT::DW_AT_low_pc)
                                .map(|v| v.as_address())
                            {
                                fun.ip_range = Some(
                                    low_pc
                                        ..entry
                                            .find_attribute(ops::DW_AT::DW_AT_high_pc)
                                            .unwrap()
                                            .as_offset_or_address(low_pc),
                                );
                            }

                            if fun.return_type.is_none() {
                                fun.return_type = entry
                                    .find_attribute(ops::DW_AT::DW_AT_type)
                                    .map(|v| mk_ty_id(v.as_entry_index()));
                            }

                            if entry.children {
                                function_index = Some(items.functions.len());
                                items.functions.push(fun);
                            }
                        }
                    }
                }

                if let Some(fun) = parents.last_mut().and_then(|x| x.function_index) {
                    let fun = &mut items.functions[fun];
                    if entry.tag == ops::DW_TAG::DW_TAG_formal_parameter {
                        fun.parameters.push(Parameter {
                            name: entry
                                .find_attribute(ops::DW_AT::DW_AT_name)
                                .map(|v| v.as_string()),
                            type_: entry
                                .find_attribute(ops::DW_AT::DW_AT_type)
                                .map(|v| mk_ty_id(v.as_entry_index()))
                                .unwrap(),
                            artificial: entry
                                .find_attribute(ops::DW_AT::DW_AT_artificial)
                                .is_some_and(|v| v.as_flag()),
                        });
                    }
                }
            }

            'type_: {
                let self_ty_id = mk_ty_id(ei);
                let type_ = Type {
                    name: entry
                        .find_attribute(ops::DW_AT::DW_AT_name)
                        .map(|v| (path.clone(), v.as_string())),
                    incomplete: entry.is_incomplete(),
                    kind: match entry.tag {
                        ops::DW_TAG::DW_TAG_base_type => TypeKind::Base {
                            encoding: ops::DW_ATE::from_value(
                                entry
                                    .find_attribute(ops::DW_AT::DW_AT_encoding)
                                    .unwrap()
                                    .as_unsigned(),
                            )
                            .unwrap(),
                            width: entry
                                .find_attribute(ops::DW_AT::DW_AT_byte_size)
                                .map(|x| x.as_unsigned() * 8)
                                .unwrap_or_else(|| {
                                    entry
                                        .find_attribute(ops::DW_AT::DW_AT_bit_size)
                                        .map(|x| x.as_unsigned())
                                        .unwrap()
                                }) as u32,
                        },
                        ops::DW_TAG::DW_TAG_typedef => TypeKind::Typedef {
                            type_: entry
                                .find_attribute(ops::DW_AT::DW_AT_type)
                                .map(|v| mk_ty_id(v.as_entry_index())),
                        },
                        ops::DW_TAG::DW_TAG_structure_type | ops::DW_TAG::DW_TAG_class_type => {
                            TypeKind::Structure(StructureType {
                                class: entry.tag == ops::DW_TAG::DW_TAG_class_type,
                                anonymous: entry
                                    .find_attribute(ops::DW_AT::DW_AT_export_symbols)
                                    .is_some_and(|v| v.as_flag()),
                                members: Vec::new(),
                            })
                        }
                        ops::DW_TAG::DW_TAG_enumeration_type => TypeKind::Enum,
                        ops::DW_TAG::DW_TAG_array_type => TypeKind::Array {
                            dimensions: {
                                EntryChildrenIterator::new(ei, entries)
                                    .map(|entry| {
                                        assert_eq!(entry.tag, ops::DW_TAG::DW_TAG_subrange_type);
                                        ArrayDimension {
                                            base_type: entry
                                                .find_attribute(ops::DW_AT::DW_AT_type)
                                                .map(|v| mk_ty_id(v.as_entry_index())),
                                            lower_bound: entry
                                                .find_attribute(ops::DW_AT::DW_AT_lower_bound)
                                                .and_then(|v| {
                                                    // looking these up would be painful and I don't use these bounds anyway
                                                    if matches!(v, AttrValue::EntryIndex(..)) {
                                                        None
                                                    } else {
                                                        Some(v.as_unsigned())
                                                    }
                                                }),
                                            upper_bound: entry
                                                .find_attribute(ops::DW_AT::DW_AT_upper_bound)
                                                .and_then(|v| {
                                                    // see above
                                                    if matches!(v, AttrValue::EntryIndex(..)) {
                                                        None
                                                    } else {
                                                        Some(v.as_unsigned())
                                                    }
                                                }),
                                        }
                                    })
                                    .collect()
                            },
                            element_type: entry
                                .find_attribute(ops::DW_AT::DW_AT_type)
                                .map(|v| mk_ty_id(v.as_entry_index()))
                                .unwrap(),
                        },
                        ops::DW_TAG::DW_TAG_pointer_type => TypeKind::Pointer {
                            type_: entry
                                .find_attribute(ops::DW_AT::DW_AT_type)
                                .map(|v| mk_ty_id(v.as_entry_index())),
                        },
                        // when let guards in match stable :sob:
                        modified if TypeModifier::from_tag(modified).is_some() => {
                            let modifier = TypeModifier::from_tag(modified).unwrap();
                            let Some(inner) = entry.find_attribute(ops::DW_AT::DW_AT_type) else {
                                // eprintln!("invalid modifier type entry {entry:?}");
                                break 'type_;
                            };
                            TypeKind::Modified {
                                modifier,
                                type_: mk_ty_id(inner.as_entry_index()),
                            }
                        }
                        _ => break 'type_,
                    },
                };

                if !entry.is_incomplete() || !items.types.contains_key(&self_ty_id) {
                    items.types.insert(self_ty_id, type_);
                }
            }

            if entry.children {
                let mut is_part_of_path = false;

                // promptly ignore ops::DW_TAG::DW_TAG_union_type
                if entry.tag == ops::DW_TAG::DW_TAG_class_type
                    || entry.tag == ops::DW_TAG::DW_TAG_structure_type
                {
                    path.push(PathItem::Structure(mk_ty_id(ei)));
                    is_part_of_path = true;
                } else if entry.tag == ops::DW_TAG::DW_TAG_namespace {
                    if let Some(name) = entry.find_attribute(ops::DW_AT::DW_AT_name) {
                        path.push(PathItem::Namespace(name.as_string()));
                        is_part_of_path = true;
                    }
                }

                parents.push(Parent {
                    idx: ei,
                    is_part_of_path,
                    entry,
                    function_index,
                });
            }
        }
        assert!(parents.is_empty());
    }

    items
}
