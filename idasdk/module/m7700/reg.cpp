
#include "m7700.hpp"
#include <segregs.hpp>

// The netnode helper.
// Using this node we will save current configuration information in the
// IDA database.
static netnode helper;

// Current processor type
processor_subtype_t ptype;

// 740 registers names
static const char *const RegNames[] =
{
  "A",        // accumulator A
  "B",        // accumulator B
  "X",        // index register X
  "Y",        // index register Y
  "S",        // stack pointer
  "PC",       // program counter
  "PG",       // program bank register
  "DT",       // data bank register
  "PS",       // processor status register
  "DPR",      // direct page register
  "fM",       // data length flag
  "fX",       // index register length flag
  "cs", "ds"  // these 2 registers are required by the IDA kernel
};

static ioports_t ports;
qstring device;
static const char cfgname[] = "m7700.cfg";

inline void get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, cfgname, bufsize);
}

// include IO common routines (such as set_device_name, apply_config_file, etc..)
#define NO_GET_CFG_PATH
#include "../iocommon.cpp"

static bool choose_device()
{
  bool ok = choose_ioport_device(&device, cfgname);
  if ( !ok )
    device = NONEPROC;
  return ok;
}

const ioport_bit_t *find_bit(ea_t address, size_t bit)
{
  return find_ioport_bit(ports, address, bit);
}

const char *idaapi set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/)
{
    if ( keyword != NULL )
        return IDPOPT_BADKEY;

    if ( !choose_ioport_device(&device, cfgname)
      && device == NONEPROC )
    {
      warning("No devices are defined in the configuration file %s", cfgname);
    }
    else
    {
      if ( helper.supstr(&device, -1) > 0 )
        set_device_name(device.c_str(), IORESP_ALL);
    }
    return IDPOPT_OK;
}

static ssize_t idaapi idb_callback(void *, int code, va_list va)
{
  switch ( code )
  {
    case idb_event::savebase:
    case idb_event::closebase:
      helper.supset(-1, device.c_str());
      break;

    case idb_event::sgr_changed:
      {
        ea_t ea1 = va_arg(va, ea_t);
        ea_t ea2 = va_arg(va, ea_t);
        int reg  = va_arg(va, int);
        sel_t v  = va_arg(va, sel_t);
        sel_t ov = va_arg(va, sel_t);
        if ( (reg == rfM || reg == rfX) && v != ov )
          set_sreg_at_next_code(ea1, ea2, reg, ov);
      }
      break;
  }
  return 0;
}

static const char *const m7700_help_message =
  "AUTOHIDE REGISTRY\n"
  "You have loaded a file for the Mitsubishi 7700 family processor.\n\n"\
  "This processor can be used in two different 'length modes' : 8-bit and 16-bit.\n"\
  "IDA allows to specify the encoding mode for every single instruction.\n"\
  "For this, IDA uses two virtual segment registers : \n"\
  "   - fM, used to specify the data length;\n"\
  "   - fX, used to specify the index register length.\n\n"\
  "Switching their state from 0 to 1 will switch the disassembly from 16-bit to 8-bit.\n"\
  "You can change their value using the 'change segment register value' command\n"\
  "(the canonical hotkey is Alt-G).\n\n"\
  "Note : in the real design, those registers are represented as flags in the\n"\
  "processor status register.\n";

// The kernel event notifications
// Here you may take desired actions upon some kernel events
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_to_notification_point(HT_IDB, idb_callback);
      helper.create("$ m7700");
      break;

    case processor_t::ev_newfile:
      if ( choose_device() )
        set_device_name(device.c_str(), IORESP_ALL);
      //  Set the default segment register values :
      //      -1 (badsel) for DR
      //      0 for fM and fX
      for ( segment_t *s=get_first_seg(); s != NULL; s=get_next_seg(s->start_ea) )
      {
        set_default_sreg_value(s, rDR, BADSEL);
        set_default_sreg_value(s, rfM, 0);
        set_default_sreg_value(s, rfX, 0);
      }
      info(m7700_help_message);
      break;

    case processor_t::ev_term:
      ports.clear();
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    case processor_t::ev_newprc:
      ptype = processor_subtype_t(va_arg(va, int));
      break;

    case processor_t::ev_oldfile:
      helper.create("$ m7700");
      if ( helper.supstr(&device, -1) > 0 )
        set_device_name(device.c_str(), IORESP_ALL);
      break;

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m7700_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m7700_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        m7700_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m7700_assumes(*ctx);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
        return 1;
      }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        const func_t *pfn = va_arg(va, const func_t *);
        *frsize = idp_get_frame_retsize(pfn);
        return 1;
      }

    case processor_t::ev_set_idp_options:
      {
        const char *keyword = va_arg(va, const char *);
        int value_type = va_arg(va, int);
        const char *value = va_arg(va, const char *);
        const char *ret = set_idp_options(keyword, value_type, value);
        if ( ret == IDPOPT_OK )
          return 1;
        const char **errmsg = va_arg(va, const char **);
        if ( errmsg != NULL )
          *errmsg = ret;
        return -1;
      }

    default:
      break;
  }
  return code;
}

static const asm_t as_asm =
{
  AS_COLON |
  ASH_HEXF4 |        // hex $123 format
  ASB_BINF3 |        // bin 0b010 format
  ASO_OCTF5 |        // oct 123q format
  AS_1TEXT,          // 1 text per line, no bytes
  UAS_SEGM|UAS_INDX_NOSPACE,
  "Alfred Arnold's Macro Assembler",
  0,
  NULL,         // no headers
  "ORG",        // origin directive
  "END",        // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "DB",         // ascii string directive
  "DB",         // byte directive
  "DW",         // word directive
  "DD",         // dword  (4 bytes)
  "DQ",         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  "DT",         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  "equ",        // Equ
  NULL,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "!",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
  0,            // flag2 ???
  NULL,         // comment close string
  NULL,         // low8 op
  NULL,         // high8 op
  NULL,         // low16 op
  NULL          // high16 op
};

//
//  Mitsubishi Macro Assembler for 7700 Family
//

//--------------------------------------------------------------------------
// gets a function name
//lint -e{818} could be declared const
static bool mits_get_func_name(qstring *name, func_t *pfn)
{
  ea_t ea = pfn->start_ea;
  if ( get_demangled_name(name, ea, inf.long_demnames, DEMNAM_NAME) <= 0 )
    return false;

  tag_addr(name, ea, true);
  return true;
}

//--------------------------------------------------------------------------
// prints function header
static void idaapi mits_func_header(outctx_t &ctx, func_t *pfn)
{
  ctx.gen_func_header(pfn);

  qstring name;
  if ( mits_get_func_name(&name, pfn) )
  {
    ctx.gen_printf(inf.indent, COLSTR(".FUNC %s", SCOLOR_ASMDIR), name.begin());
    ctx.gen_printf(0, COLSTR("%s:", SCOLOR_ASMDIR), name.begin());
    ctx.ctxflags |= CTXF_LABEL_OK;
  }
}

//--------------------------------------------------------------------------
// prints function footer
static void idaapi mits_func_footer(outctx_t &ctx, func_t *pfn)
{
  qstring name;
  if ( mits_get_func_name(&name, pfn) )
    ctx.gen_printf(inf.indent, COLSTR(".ENDFUNC %s", SCOLOR_ASMDIR), name.begin());
}

static const asm_t mitsubishi_asm =
{
  AS_COLON |
  ASH_HEXF0 |        // hex 123h format
  ASB_BINF0 |        // bin 10100011b format
  ASO_OCTF0 |        // oct 123o format
  AS_1TEXT,          // 1 text per line, no bytes
  UAS_END_WITHOUT_LABEL|UAS_DEVICE_DIR|UAS_BITMASK_LIST,
  "Mitsubishi Macro Assembler for 7700 Family",
  0,
  NULL,         // no headers
  ".ORG",       // origin directive
  ".END",       // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".BYTE",       // ascii string directive
  ".BYTE",      // byte directive
  ".WORD",      // word directive
  ".DWORD",     // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".BLKB %s",   // uninited arrays
  ".EQU",       // Equ
  NULL,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  mits_func_header,    // func_header
  mits_func_footer,    // func_footer
  ".PUB",       // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "!",          // not
  "<<",         // shl
  ">>",         // shr
  "SIZEOF",     // sizeof
  0,            // flag2 ???
  NULL,         // comment close string
  NULL,         // low8 op
  NULL,         // high8 op
  NULL,         // low16 op
  NULL          // high16 op
};

// Supported assemblers
static const asm_t *const asms[] = { &mitsubishi_asm, &as_asm, NULL };

// Short and long name for our module
#define FAMILY "Mitsubishi 16-BIT 7700 family:"

static const char *const shnames[] =
{
  "m7700",
  "m7750",
  NULL
};

static const char *const lnames[] =
{
  FAMILY"Mitsubishi 16-BIT 7700 family",
  "Mitsubishi 16-BIT 7700 family (7750 series)",
  NULL
};

static const uchar retcode_1[] = { 0x40 };    // rti
static const uchar retcode_2[] = { 0x60 };    // rts
static const uchar retcode_3[] = { 0x6B };    // rtl

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { 0, NULL }                            // NULL terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_M7700,             // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_BINMEM             // The module creates RAM/ROM segments for binary files
                          // (the kernel shouldn't ask the user about their sizes and addresses)
  | PR_SEGS               // has segment registers?
  | PR_SGROTHER,          // the segment registers don't contain
                          // the segment selectors, something else
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  RegNames,             // Regsiter names
  qnumber(RegNames),    // Number of registers

  rDR, rVds,
  2,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0, m7700_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  m7700_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
};
