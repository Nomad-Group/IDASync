
#include "m740.hpp"

// The netnode helper.
// Using this node we will save current configuration information in the
// IDA database.
static netnode helper;

// 740 registers names
static const char *const RegNames[] =
{
  "A",                // accumulator
  "X",                // index register X
  "Y",                // index register Y
  "S",                // stack pointer
  "PS",               // processor status register
  "cs", "ds"          // these 2 registers are required by the IDA kernel
};

static ioports_t ports;
qstring device;

// include IO common routines (such as set_device_name, apply_config_file, etc..)
#include "../iocommon.cpp"

const char *idaapi set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/)
{
  if ( keyword != NULL )
      return IDPOPT_BADKEY;

  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(&device, cfgfile) )
  {
    if ( device == NONEPROC )
      warning("No devices are defined in the configuration file %s", cfgfile);
  }
  else
  {
    set_device_name(device.c_str(), IORESP_ALL);
  }
  return IDPOPT_OK;
}

static ssize_t idaapi idb_callback(void *, int code, va_list /*va*/)
{
  switch ( code )
  {
    case idb_event::savebase:
    case idb_event::closebase:
      helper.supset(-1, device.c_str());
      break;
  }
  return 0;
}

// The kernel event notifications
// Here you may take desired actions upon some kernel events
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_to_notification_point(HT_IDB, idb_callback);
      helper.create("$ m740");
      break;

    case processor_t::ev_term:
      ports.clear();
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    case processor_t::ev_newfile:
      set_idp_options(NULL, 0, NULL);
      break;

    case processor_t::ev_oldfile:
      {
        if ( helper.supstr(&device, -1) > 0 )
          set_device_name(device.c_str(), IORESP_ALL);
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m740_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m740_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        m740_segstart(*ctx, seg);
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

  "BYT",        // ascii string directive
  "BYT",        // byte directive (alias: DB)
  NULL,         // word directive (alias: DW)
  NULL,         // dword  (4 bytes, alias: DD)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
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

static const asm_t iar_asm =
{
  AS_COLON |
  ASH_HEXF4 |        // hex $123 format
  ASB_BINF3 |        // bin 0b010 format
  ASO_OCTF5 |        // oct 123q format
  AS_1TEXT,          // 1 text per line, no bytes
  UAS_RSEG,
  "IAR 740 Assembler",
  0,
  NULL,         // no headers
  "ORG",        // origin directive
  "END",        // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "BYTE",       // ascii string directive
  "BYTE",       // byte directive (alias: DB)
  "WORD",       // word directive (alias: DW)
  "DWORD",      // dword  (4 bytes, alias: DD)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "BLKB %s",     // uninited arrays
  "EQU",        // Equ
  NULL,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  NULL,         // func_header
  NULL,         // func_footer
  "PUBLIC",     // public
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
static const asm_t *const asms[] = { &as_asm, &iar_asm, NULL };

// Short and long name for our module
#define FAMILY "Mitsubishi 8-BIT 740 family:"

static const char *const shnames[] =
{
  "m740",
  NULL
};

static const char *const lnames[] =
{
  FAMILY"Mitsubishi 8-BIT 740 family",
  NULL
};

static const uchar retcode_1[] = { 0x40 };    // rti
static const uchar retcode_2[] = { 0x60 };    // rts

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { 0, NULL }                            // NULL terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_M740,              // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_BINMEM,            // The module creates RAM/ROM segments for binary files
                          // (the kernel shouldn't ask the user about their sizes and addresses)
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

  rVcs,rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0, m740_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  m740_rts,             // Icode of return instruction. It is ok to give any of possible return instructions
};
