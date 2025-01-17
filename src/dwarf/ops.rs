use super::{MutBytes, SliceExt, sleb128, uleb128};

// macro adapted from another one of my projects
// instead of writing, we read the ops
macro_rules! define_dwarf_op {
    ($name: ident, $code: literal $(, $operand_name: ident: $operand_type: tt)*) => {
        #[derive(Debug, Clone, Copy)]
        #[allow(non_camel_case_types, dead_code)]
        pub struct $name {
            $($operand_name: define_dwarf_op!(@operand_value_type $operand_type)),*
        }

        impl $name {
            pub fn take(input: super::MutBytes) -> Self {
                let code = input.consume_first();
                if code != $code {
                    panic!(concat!("tried to take a ", stringify!($name), " but got a {:X} opcode"), code)
                }

                Self {
                    $($operand_name: define_dwarf_op!(@read_operand $operand_type, input)),*
                }
            }
        }
    };
    (@operand_value_type 1u) => { u8 };
    (@operand_value_type 1s) => { i8 };
    (@operand_value_type 2u) => { u16 };
    (@operand_value_type 2s) => { i16 };
    (@operand_value_type 4u) => { u32 };
    (@operand_value_type 4s) => { i32 };
    (@operand_value_type 8u) => { u64 };
    (@operand_value_type 8s) => { i64 };
    (@operand_value_type uleb128) => { u64 };
    (@operand_value_type sleb128) => { i64 };
    (@operand_value_type address) => { usize };
    (@read_operand 1u, $in: ident) => { $in.consume_first() };
    (@read_operand 1s, $in: ident) => { i8::from_le_bytes(*$in.consume_chunk::<1>()) };
    (@read_operand 2u, $in: ident) => { u16::from_le_bytes(*$in.consume_chunk::<2>()) };
    (@read_operand 2s, $in: ident) => { i16::from_le_bytes(*$in.consume_chunk::<2>())  };
    (@read_operand 4u, $in: ident) => { u32::from_le_bytes(*$in.consume_chunk::<4>()) };
    (@read_operand 4s, $in: ident) => { i32::from_le_bytes(*$in.consume_chunk::<4>())  };
    (@read_operand 8u, $in: ident) => { u64::from_le_bytes(*$in.consume_chunk::<8>()) };
    (@read_operand 8s, $in: ident) => { i64::from_le_bytes(*$in.consume_chunk::<8>())  };
    (@read_operand address, $in: ident) => { };
    (@read_operand uleb128, $in: ident) => { uleb128($in) };
    (@read_operand sleb128, $in: ident) => { sleb128($in) };
}

macro_rules! define_dwarf_ops {
    {
        enum $enum: ident;
        $($name: ident[$opcode: literal](
            $($aname: tt: $atype: tt),*
        );)*
    } => {
        $(define_dwarf_op!($name, $opcode $(, $aname: $atype)*);)*

        #[derive(Debug, Clone, Copy)]
        #[allow(non_camel_case_types, dead_code, clippy::enum_variant_names)]
        pub enum $enum {
            $($name($name),)*
        }

        impl $enum {
            #[allow(non_snake_case, dead_code)]
            pub fn try_take(input: MutBytes) -> Option<$enum> {
                match input[0] {
                    $($opcode => Some({$enum::$name($name::take(input))}),)*
                    _ => None
                }
            }

            #[allow(non_snake_case, dead_code)]
            pub fn take(input: MutBytes) -> Self {
                match Self::try_take(input) {
                    Some(r) => r,
                    None => panic!(concat!("unknown ", stringify!($enum), ": 0x{:02X}"), input[0])
                }
            }
        }
    };
}

// FIXME: these are from v5
define_dwarf_ops! {
    enum DW_OP;
    DW_OP_addr[0x03](value: 8u); // assume 64 bit address
    DW_OP_deref[0x06]();
    DW_OP_const1u[0x08](value: 1u);
    DW_OP_const1s[0x09](value: 1s);
    DW_OP_const2u[0x0a](value: 2u);
    DW_OP_const2s[0x0b](value: 2s);
    DW_OP_const4u[0x0c](value: 4u);
    DW_OP_const4s[0x0d](value: 4s);
    DW_OP_const8u[0x0e](value: 8u);
    DW_OP_const8s[0x0f](value: 8s);
    DW_OP_constu[0x10](value: uleb128);
    DW_OP_consts[0x11](value: sleb128);
    DW_OP_dup[0x12]();
    DW_OP_drop[0x13]();
    DW_OP_over[0x14]();
    DW_OP_pick[0x15](value: 1u);
    DW_OP_swap[0x16]();
    DW_OP_rot[0x17]();
    DW_OP_xderef[0x18]();
    DW_OP_abs[0x19]();
    DW_OP_and[0x1a]();
    DW_OP_div[0x1b]();
    DW_OP_minus[0x1c]();
    DW_OP_mod[0x1d]();
    DW_OP_mul[0x1e]();
    DW_OP_neg[0x1f]();
    DW_OP_not[0x20]();
    DW_OP_or[0x21]();
    DW_OP_plus[0x22]();
    DW_OP_plus_uconst[0x23](addend: uleb128);
    DW_OP_shl[0x24]();
    DW_OP_shr[0x25]();
    DW_OP_shra[0x26]();
    DW_OP_xor[0x27]();
    DW_OP_bra[0x28](operand: 2u);
    DW_OP_eq[0x29]();
    DW_OP_ge[0x2a]();
    DW_OP_gt[0x2b]();
    DW_OP_le[0x2c]();
    DW_OP_lt[0x2d]();
    DW_OP_ne[0x2e]();
    DW_OP_skip[0x2f]();

    // DW_OP_list0..31
    DW_OP_lit0[0x30]();
    DW_OP_lit1[0x31]();
    DW_OP_lit2[0x32]();
    DW_OP_lit3[0x33]();
    DW_OP_lit4[0x34]();
    DW_OP_lit5[0x35]();
    DW_OP_lit6[0x36]();
    DW_OP_lit7[0x37]();
    DW_OP_lit8[0x38]();
    DW_OP_lit9[0x39]();
    DW_OP_lit10[0x3a]();
    DW_OP_lit11[0x3b]();
    DW_OP_lit12[0x3c]();
    DW_OP_lit13[0x3d]();
    DW_OP_lit14[0x3e]();
    DW_OP_lit15[0x3f]();
    DW_OP_lit16[0x40]();
    DW_OP_lit17[0x41]();
    DW_OP_lit18[0x42]();
    DW_OP_lit19[0x43]();
    DW_OP_lit20[0x44]();
    DW_OP_lit21[0x45]();
    DW_OP_lit22[0x46]();
    DW_OP_lit23[0x47]();
    DW_OP_lit24[0x48]();
    DW_OP_lit25[0x49]();
    DW_OP_lit26[0x4a]();
    DW_OP_lit27[0x4b]();
    DW_OP_lit28[0x4c]();
    DW_OP_lit29[0x4d]();
    DW_OP_lit30[0x4e]();
    DW_OP_lit31[0x4f]();

    // DW_OP_reg0..31
    DW_OP_reg0[0x50]();
    DW_OP_reg1[0x51]();
    DW_OP_reg2[0x52]();
    DW_OP_reg3[0x53]();
    DW_OP_reg4[0x54]();
    DW_OP_reg5[0x55]();
    DW_OP_reg6[0x56]();
    DW_OP_reg7[0x57]();
    DW_OP_reg8[0x58]();
    DW_OP_reg9[0x59]();
    DW_OP_reg10[0x5a]();
    DW_OP_reg11[0x5b]();
    DW_OP_reg12[0x5c]();
    DW_OP_reg13[0x5d]();
    DW_OP_reg14[0x5e]();
    DW_OP_reg15[0x5f]();
    DW_OP_reg16[0x60]();
    DW_OP_reg17[0x61]();
    DW_OP_reg18[0x62]();
    DW_OP_reg19[0x63]();
    DW_OP_reg20[0x64]();
    DW_OP_reg21[0x65]();
    DW_OP_reg22[0x66]();
    DW_OP_reg23[0x67]();
    DW_OP_reg24[0x68]();
    DW_OP_reg25[0x69]();
    DW_OP_reg26[0x6a]();
    DW_OP_reg27[0x6b]();
    DW_OP_reg28[0x6c]();
    DW_OP_reg29[0x6d]();
    DW_OP_reg30[0x6e]();
    DW_OP_reg31[0x6f]();

    // DW_breg_reg0..31
    DW_OP_bref0[0x70](offset: sleb128);
    DW_OP_bref1[0x71](offset: sleb128);
    DW_OP_bref2[0x72](offset: sleb128);
    DW_OP_bref3[0x73](offset: sleb128);
    DW_OP_bref4[0x74](offset: sleb128);
    DW_OP_bref5[0x75](offset: sleb128);
    DW_OP_bref6[0x76](offset: sleb128);
    DW_OP_bref7[0x77](offset: sleb128);
    DW_OP_bref8[0x78](offset: sleb128);
    DW_OP_bref9[0x79](offset: sleb128);
    DW_OP_bref10[0x7a](offset: sleb128);
    DW_OP_bref11[0x7b](offset: sleb128);
    DW_OP_bref12[0x7c](offset: sleb128);
    DW_OP_bref13[0x7d](offset: sleb128);
    DW_OP_bref14[0x7e](offset: sleb128);
    DW_OP_bref15[0x7f](offset: sleb128);
    DW_OP_bref16[0x80](offset: sleb128);
    DW_OP_bref17[0x81](offset: sleb128);
    DW_OP_bref18[0x82](offset: sleb128);
    DW_OP_bref19[0x83](offset: sleb128);
    DW_OP_bref20[0x84](offset: sleb128);
    DW_OP_bref21[0x85](offset: sleb128);
    DW_OP_bref22[0x86](offset: sleb128);
    DW_OP_bref23[0x87](offset: sleb128);
    DW_OP_bref24[0x88](offset: sleb128);
    DW_OP_bref25[0x89](offset: sleb128);
    DW_OP_bref26[0x8a](offset: sleb128);
    DW_OP_bref27[0x8b](offset: sleb128);
    DW_OP_bref28[0x8c](offset: sleb128);
    DW_OP_bref29[0x8d](offset: sleb128);
    DW_OP_bref30[0x8e](offset: sleb128);
    DW_OP_bref31[0x8f](offset: sleb128);

    DW_OP_regx[0x90](register: uleb128);
    DW_OP_fbreg[0x91](offset: sleb128);
    DW_OP_bregx[0x92](register: uleb128, offset: sleb128);
    DW_OP_piece[0x93](size: uleb128);
    DW_OP_deref_size[0x94](size: 1u);
    DW_OP_xderef_size[0x95](size: 1u);
    DW_OP_nop[0x96]();
    DW_OP_push_object_address[0x97]();
    DW_OP_call2[0x98](offset: 2u);
    DW_OP_call4[0x99](offset: 4u);
    // DW_OP_call_ref[0x9a](offset: dependent on dwarf bitness, not supported);
    DW_OP_form_tls_address[0x9b]();
    DW_OP_call_frame_cfa[0x9c]();
    DW_OP_bit_piece[0x9d](size: uleb128, offset: uleb128);
    // DW_OP_implicit_value takes a variable size immediate, not supported
    DW_OP_stack_value[0x9f]();
    // DWARF5 operations are somewhat more nuanced and I don't need them, not supported
}

macro_rules! define_dwarf_enum {
    {
        enum $enum: ident $(($user: ident $ustart: literal .. $uend: literal))?;
        $($name: ident[$opcode: literal];)*
    } => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[allow(non_camel_case_types, dead_code, clippy::enum_variant_names)]
        pub enum $enum {
            $($name,)*
            $($user(u64))?
        }

        impl $enum {
            #[allow(non_snake_case, dead_code)]
            pub fn from_value(value: u64) -> Option<Self> {
                match value {
                    $($opcode => Some(Self::$name),)*
                    $($ustart..$uend => Some(Self::$user(value)),)?
                    _ => None
                }
            }

            #[allow(non_snake_case, dead_code)]
            pub fn value(self) -> u64 {
                match self {
                    $(Self::$name => $opcode,)*
                    $(Self::$user(user) => user,)?
                }
            }


            #[allow(non_snake_case, dead_code)]
            pub fn take(input: MutBytes) -> Self {
                let value = uleb128(input);
                match Self::from_value(value) {
                    Some(r) => r,
                    _ => panic!(concat!("unknown ", stringify!($enum), ": 0x{:04X}"), value)
                }
            }
        }
    };
}

define_dwarf_enum! {
    enum DW_TAG (DW_TAG_user 0x4080..0xffff);
    DW_TAG_array_type[0x01];
    DW_TAG_class_type[0x02];
    DW_TAG_entry_point[0x03];
    DW_TAG_enumeration_type[0x04];
    DW_TAG_formal_parameter[0x05];
    DW_TAG_imported_declaration[0x08];
    DW_TAG_label[0x0a];
    DW_TAG_lexical_block[0x0b];
    DW_TAG_member[0x0d];
    DW_TAG_pointer_type[0x0f];
    DW_TAG_reference_type[0x10];
    DW_TAG_compile_unit[0x11];
    DW_TAG_string_type[0x12];
    DW_TAG_structure_type[0x13];
    DW_TAG_subroutine_type[0x15];
    DW_TAG_typedef[0x16];
    DW_TAG_union_type[0x17];
    DW_TAG_unspecified_parameters[0x18];
    DW_TAG_variant[0x19];
    DW_TAG_common_block[0x1a];
    DW_TAG_common_inclusion[0x1b];
    DW_TAG_inheritance[0x1c];
    DW_TAG_inlined_subroutine[0x1d];
    DW_TAG_module[0x1e];
    DW_TAG_ptr_to_member_type[0x1f];
    DW_TAG_set_type[0x20];
    DW_TAG_subrange_type[0x21];
    DW_TAG_with_stmt[0x22];
    DW_TAG_access_declaration[0x23];
    DW_TAG_base_type[0x24];
    DW_TAG_catch_block[0x25];
    DW_TAG_const_type[0x26];
    DW_TAG_constant[0x27];
    DW_TAG_enumerator[0x28];
    DW_TAG_file_type[0x29];
    DW_TAG_friend[0x2a];
    DW_TAG_namelist[0x2b];
    DW_TAG_namelist_item[0x2c];
    DW_TAG_packed_type[0x2d];
    DW_TAG_subprogram[0x2e];
    DW_TAG_template_type_parameter[0x2f];
    DW_TAG_template_value_parameter[0x30];
    DW_TAG_thrown_type[0x31];
    DW_TAG_try_block[0x32];
    DW_TAG_variant_part[0x33];
    DW_TAG_variable[0x34];
    DW_TAG_volatile_type[0x35];
    DW_TAG_dwarf_procedure[0x36];
    DW_TAG_restrict_type[0x37];
    DW_TAG_interface_type[0x38];
    DW_TAG_namespace[0x39];
    DW_TAG_imported_module[0x3a];
    DW_TAG_unspecified_type[0x3b];
    DW_TAG_partial_unit[0x3c];
    DW_TAG_imported_unit[0x3d];
    DW_TAG_condition[0x3f];
    DW_TAG_shared_type[0x40];
    DW_TAG_type_unit[0x41];
    DW_TAG_rvalue_reference_type[0x42];
    DW_TAG_template_alias[0x43];
    DW_TAG_coarray_type[0x44];
    DW_TAG_generic_subrange[0x45];
    DW_TAG_dynamic_type[0x46];
    DW_TAG_atomic_type[0x47];
    DW_TAG_call_site[0x48];
    DW_TAG_call_site_parameter[ 0x49];
    DW_TAG_skeleton_unit[0x4a];
    DW_TAG_immutable_type[0x4b];
}

define_dwarf_enum! {
    enum DW_AT (DW_AT_user 0x2000..0x3fff);
    DW_AT_sibling[0x01];
    DW_AT_location[0x02];
    DW_AT_name[0x03];
    DW_AT_ordering[0x09];
    DW_AT_byte_size[0x0b];
    DW_AT_bit_offset[0x0c];
    DW_AT_bit_size[0x0d];
    DW_AT_stmt_list[0x10];
    DW_AT_low_pc[0x11];
    DW_AT_high_pc[0x12];
    DW_AT_language[0x13];
    DW_AT_discr[0x15];
    DW_AT_discr_value[0x16];
    DW_AT_visibility[0x17];
    DW_AT_import[0x18];
    DW_AT_string_length[0x19];
    DW_AT_common_reference[0x1a];
    DW_AT_comp_dir[0x1b];
    DW_AT_const_value[0x1c];
    DW_AT_containing_type[0x1d];
    DW_AT_default_value[0x1e];
    DW_AT_inline[0x20];
    DW_AT_is_optional[0x21];
    DW_AT_lower_bound[0x22];
    DW_AT_producer[0x25];
    DW_AT_prototyped[0x27];
    DW_AT_return_addr[0x2a];
    DW_AT_start_scope[0x2c];
    DW_AT_bit_stride[0x2e];
    DW_AT_upper_bound[0x2f];
    DW_AT_abstract_origin[0x31];
    DW_AT_accessibility[0x32];
    DW_AT_address_class[0x33];
    DW_AT_artificial[0x34];
    DW_AT_base_types[0x35];
    DW_AT_calling_convention[0x36];
    DW_AT_count[0x37];
    DW_AT_data_member_location[0x38];
    DW_AT_decl_column[0x39];
    DW_AT_decl_file[0x3a];
    DW_AT_decl_line[0x3b];
    DW_AT_declaration[0x3c];
    DW_AT_discr_list[0x3d];
    DW_AT_encoding[0x3e];
    DW_AT_external[0x3f];
    DW_AT_frame_base[0x40];
    DW_AT_friend[0x41];
    DW_AT_identifier_case[0x42];
    DW_AT_macro_info[0x43];
    DW_AT_namelist_item[0x44];
    DW_AT_priority[0x45];
    DW_AT_segment[0x46];
    DW_AT_specification[0x47];
    DW_AT_static_link[0x48];
    DW_AT_type[0x49];
    DW_AT_use_location[0x4a];
    DW_AT_variable_parameter[0x4b];
    DW_AT_virtuality[0x4c];
    DW_AT_vtable_elem_location[0x4d];
    DW_AT_allocated[0x4e];
    DW_AT_associated[0x4f];
    DW_AT_data_location[0x50];
    DW_AT_byte_stride[0x51];
    DW_AT_entry_pc[0x52];
    DW_AT_use_UTF8[0x53];
    DW_AT_extension[0x54];
    DW_AT_ranges[0x55];
    DW_AT_trampoline[0x56];
    DW_AT_call_column[0x57];
    DW_AT_call_file[0x58];
    DW_AT_call_line[0x59];
    DW_AT_description[0x5a];
    DW_AT_binary_scale[0x5b];
    DW_AT_decimal_scale[0x5c];
    DW_AT_small[0x5d];
    DW_AT_decimal_sign[0x5e];
    DW_AT_digit_count[0x5f];
    DW_AT_picture_string[0x60];
    DW_AT_mutable[0x61];
    DW_AT_threads_scaled[0x62];
    DW_AT_explicit[0x63];
    DW_AT_object_pointer[0x64];
    DW_AT_endianity[0x65];
    DW_AT_elemental[0x66];
    DW_AT_pure[0x67];
    DW_AT_recursive[0x68];
    DW_AT_signature[0x69];
    DW_AT_main_subprogram[0x6a];
    DW_AT_data_bit_offset[0x6b];
    DW_AT_const_expr[0x6c];
    DW_AT_enum_class[0x6d];
    DW_AT_linkage_name[0x6e];
    DW_AT_string_length_bit_size[0x6f];
    DW_AT_string_length_byte_size[0x70];
    DW_AT_rank[0x71];
    DW_AT_str_offsets_base[0x72];
    DW_AT_addr_base[0x73];
    DW_AT_rnglists_base[0x74];
    DW_AT_dwo_name[0x76];
    DW_AT_reference[0x77];
    DW_AT_rvalue_reference[0x78];
    DW_AT_macros[0x79];
    DW_AT_call_all_calls[0x7a];
    DW_AT_call_all_source_calls[0x7b];
    DW_AT_call_all_tail_calls[0x7c];
    DW_AT_call_return_pc[0x7d];
    DW_AT_call_value[0x7e];
    DW_AT_call_origin[0x7f];
    DW_AT_call_parameter[0x80];
    DW_AT_call_pc[0x81];
    DW_AT_call_tail_call[0x82];
    DW_AT_call_target[0x83];
    DW_AT_call_target_clobbered[0x84];
    DW_AT_call_data_location[0x85];
    DW_AT_call_data_value[0x86];
    DW_AT_noreturn[0x87];
    DW_AT_alignment[0x88];
    DW_AT_export_symbols[0x89];
    DW_AT_deleted[0x8a];
    DW_AT_defaulted[0x8b];
    DW_AT_loclists_base[0x8c];
}

define_dwarf_enum! {
    enum DW_FORM;
    DW_FORM_addr[0x01];
    DW_FORM_block2[0x03];
    DW_FORM_block4[0x04];
    DW_FORM_data2[0x05];
    DW_FORM_data4[0x06];
    DW_FORM_data8[0x07];
    DW_FORM_string[0x08];
    DW_FORM_block[0x09];
    DW_FORM_block1[0x0a];
    DW_FORM_data1[0x0b];
    DW_FORM_flag[0x0c];
    DW_FORM_sdata[0x0d];
    DW_FORM_strp[0x0e];
    DW_FORM_udata[0x0f];
    DW_FORM_ref_addr[0x10];
    DW_FORM_ref1[0x11];
    DW_FORM_ref2[0x12];
    DW_FORM_ref4[0x13];
    DW_FORM_ref8[0x14];
    DW_FORM_ref_udata[0x15];
    DW_FORM_indirect[0x16];
    DW_FORM_sec_offset[0x17];
    DW_FORM_exprloc[0x18];
    DW_FORM_flag_present[0x19];
    DW_FORM_ref_sig8[0x20];
}

define_dwarf_enum! {
    enum DW_ATE (DW_ATE_user 0x80..0xff);
    DW_ATE_address[0x01];
    DW_ATE_boolean[0x02];
    DW_ATE_complex_float[0x03];
    DW_ATE_float[0x04];
    DW_ATE_signed[0x05];
    DW_ATE_signed_char[0x06];
    DW_ATE_unsigned[0x07];
    DW_ATE_unsigned_char[0x08];
    DW_ATE_imaginary_float[0x09];
    DW_ATE_packed_decimal[0x0a];
    DW_ATE_numeric_string[0x0b];
    DW_ATE_edited[0x0c];
    DW_ATE_signed_fixed[0x0d];
    DW_ATE_unsigned_fixed[0x0e];
    DW_ATE_decimal_float[0x0f];
    DW_ATE_UTF[0x10];
    DW_ATE_UCS[0x11];
    DW_ATE_ASCII[0x12];
}

define_dwarf_enum! {
    enum DW_ACCESS;
    DW_ACCESS_public[0x01];
    DW_ACCESS_protected[0x02];
    DW_ACCESS_private[0x03];
}

define_dwarf_enum! {
    enum DW_CC (DW_CC_user 0x40..0xff);
    DW_CC_program[0x02];
    DW_CC_nocall[0x03];
    DW_CC_pass_by_reference[0x04];
    DW_CC_pass_by_value[0x05];
}
