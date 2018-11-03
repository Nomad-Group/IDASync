/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2017 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

// This file contains custom fixup handlers for simplified fixups with high
// and low parts. The word "simplified" means that we don't use LR and RR
// rounding modes as prescribed in the documentation. We replace them by "
// and R rounding modes.
// They are used for the relocations:
// - R_PARISC_DIR21L, R_PARISC_DPREL21L
// - R_PARISC_DIR14R, R_PARISC_DPREL14R

#include <fixup.hpp>

//lint -esym(843, cfh_*_id)
static fixup_type_t cfh_l21_id; // ids of fixup handlers
static fixup_type_t cfh_r11_id;
//lint -esym(843, ref_*_id)
static int ref_l21_id;          // ids of refinfo handlers
static int ref_r11_id;

//--------------------------------------------------------------------------
// apply a fixup: convert the operand into an offset expression
static bool idaapi l21_apply(
        const fixup_handler_t *fh,
        ea_t item_ea,
        ea_t /*fixup_ea*/,
        int opnum,
        bool /*is_macro*/,
        const fixup_data_t &fd)
{
  if ( is_unknown(get_flags(item_ea)) )
  {
    // don't use dummy; leave it for processor module if it needs it
    insn_t tmp;
    create_insn(item_ea, &tmp);
  }

  refinfo_t ri;
  ri.flags  = fh->reftype;
  ri.base   = fd.get_base();
  ri.target = ri.base + fd.off;
  ri.tdelta = fd.displacement;
  op_offset_ex(item_ea, opnum, &ri);
  return true;
}

//--------------------------------------------------------------------------
static uval_t idaapi l21_get_value(const fixup_handler_t * /*fh*/, ea_t ea)
{
  uint32 insn = get_dword(ea);
  // extract `im21' from "Long immediate" instruction
  return as21(insn);
}

//----------------------------------------------------------------------------
static bool idaapi l21_patch_value(
        const fixup_handler_t * /*fh*/,
        ea_t ea,
        const fixup_data_t &fd)
{
  uint32 insn = get_dword(ea);
  ea_t expr = fd.off + fd.displacement;
  // 33222222222211111111110000000000
  // 10987654321098765432109876543210
  // abbbbbbbbbbbccdddddee___________ expr
  // ___________dddddcceebbbbbbbbbbba insn
  // 10987654321098765432109876543210
  uint32 im21 = (((expr >> 31) & 0x001) <<  0)  // a
              | (((expr >> 20) & 0x7FF) <<  1)  // b
              | (((expr >> 18) & 0x003) << 14)  // c
              | (((expr >> 13) & 0x01F) << 16)  // d
              | (((expr >> 11) & 0x003) << 12); // e
  put_dword(ea, (insn & 0xFFE00000) | im21);
  return true;
}

//--------------------------------------------------------------------------
//lint -esym(843, cfh_l21)
static fixup_handler_t cfh_l21 =
{
  sizeof(fixup_handler_t),
  "L21",                        // name
  0,                            // props
  4, 0, 0, 0,                   // size, width, shift
  REFINFO_CUSTOM,               // reftype
  l21_apply,                    // apply
  l21_get_value,                // get_value
  l21_patch_value,              // patch_value
};

//--------------------------------------------------------------------------
static bool idaapi l21_calc_reference_data(
        ea_t *target,
        ea_t *base,
        ea_t /*from*/,
        const refinfo_t &ri,
        adiff_t opval)
{
  if ( ri.target == BADADDR
    || ri.base == BADADDR
    || ri.is_subtract() )
  {
    return false;
  }
  ea_t fullvalue = ri.target + ri.tdelta - ri.base;
  uint32 calc_opval = fullvalue & 0xFFFFF800;
  if ( calc_opval != uint32(opval) )
    return false;

  *target = ri.target;
  *base = ri.base;
  return true;
}

//--------------------------------------------------------------------------
static void idaapi l21_get_format(qstring *format)
{
  *format = COLSTR("l%%%s", SCOLOR_KEYWORD);
}

//--------------------------------------------------------------------------
static const custom_refinfo_handler_t ref_l21 =
{
  sizeof(custom_refinfo_handler_t),
  "L21",
  "right-justified, high-order 21 bits",
  0,                        // properties (currently 0)
  NULL,                     // gen_expr
  l21_calc_reference_data,  // calc_reference_data
  l21_get_format,           // get_format
};


//--------------------------------------------------------------------------
static bool idaapi r11_apply(
        const fixup_handler_t *fh,
        ea_t item_ea,
        ea_t /*fixup_ea*/,
        int opnum,
        bool /*is_macro*/,
        const fixup_data_t &fd)
{
  if ( is_unknown(get_flags(item_ea)) )
  {
    // don't use dummy; leave it for processor module if it needs it
    insn_t tmp;
    create_insn(item_ea, &tmp);
  }

  refinfo_t ri;
  ri.flags  = fh->reftype;
  ri.base   = fd.get_base();
  ri.target = ri.base + fd.off;
  ri.tdelta = fd.displacement;
  op_offset_ex(item_ea, opnum, &ri);
  return true;
}

//--------------------------------------------------------------------------
// we use the R rounding mode (11-bit) in this fixup
// but here we return the full immediated value (14-bit or 16-bit)
static uval_t idaapi r11_get_value(const fixup_handler_t * /*fh*/, ea_t ea)
{
  uint32 insn = get_dword(ea);
  // extract `im14' from "Load/Store" instruction
  return sval_t(int16(get_ldo(insn)));
}

//----------------------------------------------------------------------------
static bool idaapi r11_patch_value(
        const fixup_handler_t * /*fh*/,
        ea_t ea,
        const fixup_data_t &fd)
{
  uint32 insn = get_dword(ea);
  // we use the R rounding mode (11-bit) in this fixup
  ea_t expr = (fd.off + fd.displacement) & 0x7FF;
  if ( psw_w() )
  {
    // 33222222222211111111110000000000
    // 10987654321098765432109876543210
    // ________________abbccccccccccccc expr
    // ________________BBccccccccccccca insn
    // 10987654321098765432109876543210
    // B = a == 0 ? b : ~b;
    uint32 a = (expr >> 15) & 0x0001;
    uint32 b = (expr >> 13) & 0x0003;
    if ( a != 0 )
      b = ~b;
    uint32 c = expr & 0x1FFF;
    uint32 im16 = a | (b << 14) | (c << 1);
    put_dword(ea, (insn & 0xFFFF0000) | im16);
  }
  else
  {
    // 33222222222211111111110000000000
    // 10987654321098765432109876543210
    // __________________abbbbbbbbbbbbb expr
    // __________________bbbbbbbbbbbbba insn
    // 10987654321098765432109876543210
    uint32 im14 = (((expr >> 13) & 0x0001) << 0)  // a
                | ((expr         & 0x1FFF) << 1); // b
    put_dword(ea, (insn & 0xFFFFC000) | im14);
  }
  return true;
}

//--------------------------------------------------------------------------
//lint -esym(843, cfh_r11)
static fixup_handler_t cfh_r11 =
{
  sizeof(fixup_handler_t),
  "R11",                        // name
  0,                            // props
  4, 0, 0, 0,                   // size, width, shift
  REFINFO_CUSTOM,               // reftype
  r11_apply,                    // apply
  r11_get_value,                // get_value
  r11_patch_value,              // patch_value
};

//--------------------------------------------------------------------------
static bool idaapi r11_calc_reference_data(
        ea_t *target,
        ea_t *base,
        ea_t /*from*/,
        const refinfo_t &ri,
        adiff_t opval)
{
  if ( ri.target == BADADDR
    || ri.base == BADADDR
    || ri.is_subtract() )
  {
    return false;
  }
  ea_t fullvalue = ri.target + ri.tdelta - ri.base;
  uint32 calc_opval = fullvalue & 0x7FF;
  if ( calc_opval != uint32(opval) )
    return false;

  *target = ri.target;
  *base = ri.base;
  return true;
}

//--------------------------------------------------------------------------
static void idaapi r11_get_format(qstring *format)
{
  *format = COLSTR("r%%%s", SCOLOR_KEYWORD);
}

//--------------------------------------------------------------------------
static const custom_refinfo_handler_t ref_r11 =
{
  sizeof(custom_refinfo_handler_t),
  "R11",
  "low-order 11 bits",
  0,                        // properties (currently 0)
  NULL,                     // gen_expr
  r11_calc_reference_data,  // calc_reference_data
  r11_get_format,           // get_format
};


//--------------------------------------------------------------------------
static void init_custom_refs()
{
  cfh_l21_id = register_custom_fixup(&cfh_l21);
  cfh_r11_id = register_custom_fixup(&cfh_r11);
  ref_l21_id = register_custom_refinfo(&ref_l21);
  ref_r11_id = register_custom_refinfo(&ref_r11);
  cfh_l21.reftype = REFINFO_CUSTOM | ref_l21_id;
  cfh_r11.reftype = REFINFO_CUSTOM | ref_r11_id;
}

//--------------------------------------------------------------------------
static void term_custom_refs()
{
  cfh_l21.reftype = REFINFO_CUSTOM;
  cfh_r11.reftype = REFINFO_CUSTOM;
  unregister_custom_refinfo(ref_r11_id);
  unregister_custom_refinfo(ref_l21_id);
  unregister_custom_fixup(cfh_r11_id);
  unregister_custom_fixup(cfh_l21_id);
}
