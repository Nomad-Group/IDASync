/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Processor description structures
 *
 */
#include "necv850.hpp"
#include "ins.hpp"
#include <loader.hpp>
#include <segregs.hpp>

// program pointers (gp, tp)
static netnode prog_pointers;
#define GP_EA_IDX 1
#define CTBP_EA_IDX 2
ea_t g_gp_ea = BADADDR; // global pointer
ea_t g_ctbp_ea = BADADDR; // CALLT base pointer

//------------------------------------------------------------------
const char *idaapi set_idp_options(
        const char *keyword,
        int value_type,
        const void *value)
{
  if ( keyword != NULL )
  {
    if ( strcmp(keyword, "GP_EA") == 0 )
    {
      if ( value_type != IDPOPT_NUM )
        return IDPOPT_BADTYPE;
      g_gp_ea = *((uval_t *)value);
      return IDPOPT_OK;
    }
    if ( streq(keyword, "CTBP_EA") )
    {
      if ( value_type != IDPOPT_NUM )
        return IDPOPT_BADTYPE;
      g_ctbp_ea = *((uval_t *)value);
      return IDPOPT_OK;
    }
    return IDPOPT_BADKEY;
  }

  static const char form[] =
    "NEC V850x analyzer options\n"
    "\n"
    " <~G~lobal Pointer address:$:16:16::>\n"
    " <CALLT ~B~ase pointer    :$:16:16::>\n"
    "\n"
    "\n"
    "\n";
  ask_form(form, &g_gp_ea, &g_ctbp_ea);

  return IDPOPT_OK;
}

//----------------------------------------------------------------------
static const asm_t nec850_asm =
{
  ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,  // flags
  0,                                // user flags
  "NEC V850 Assembler",             // assembler name
  0,                                // help
  NULL,                             // array of automatically generated header lines
  ".org",                           // org directive
  ".end",                           // end directive
  "--",                             // comment string
  '"',                              // string delimiter
  '\'',                             // char delimiter
  "'\"",                            // special symbols in char and string constants
  ".str",                           // ascii string directive
  ".byte",                          // byte directive
  ".hword",                         // word directive -- actually half a word (16bits)
  ".word",                          // double words -- actually a 32bits word
  NULL,                             // qwords
  NULL,                             // oword  (16 bytes)
  ".float",                         // float
  NULL,                             // no double
  NULL,                             // no tbytes
  NULL,                             // no packreal
  "#d dup(#v)",                     //".db.#s(b,w) #d,#v"
  ".byte (%s) ?",                   // uninited data (reserve space) ;?
  ".set",                           // 'equ' Used if AS_UNEQU is set
  NULL,                             // seg prefix
  "PC",                             // a_curip
  NULL,                             // returns function header line
  NULL,                             // returns function footer line
  ".globl",                         // public
  NULL,                             // weak
  ".extern",                        // extrn
  ".comm",                          // comm
  NULL,                             // get_type_name
  ".align",                         // align
  '(',                              // lbrace
  ')',                              // rbrace
  NULL,                             // mod
  "&",                              // bit-and
  "|",                              // or
  "^",                              // xor
  "!",                              // not
  "<<",                             // shl
  ">>",                             // shr
  NULL,                             // sizeof
  0,                                // flags2
  NULL,                             // cmnt2
  NULL,                             // low8 operation, should contain %s for the operand
  NULL,                             // high8
  NULL,                             // low16
  NULL,                             // high16
  ".include %s",                    // a_include_fmt
  NULL,                             // if a named item is a structure and displayed
  NULL                              // 'rva' keyword for image based offsets
};

static const asm_t *const asms[] = { &nec850_asm, NULL };

//----------------------------------------------------------------------
#define FAMILY "NEC series:"

static const char *const shnames[] =
{
  "V850E1",
  "V850",
  NULL
};

static const char *const lnames[] =
{
  FAMILY"NEC V850E1/ES",
  "NEC V850",
  NULL
};

//--------------------------------------------------------------------------
static ssize_t idaapi idb_callback(void *, int code, va_list /*va*/)
{
  switch ( code )
  {
    // save database
    case idb_event::closebase:
    case idb_event::savebase:
      prog_pointers.altset(GP_EA_IDX, ea2node(g_gp_ea));
      prog_pointers.altset(CTBP_EA_IDX, ea2node(g_ctbp_ea));
      break;

    case idb_event::segm_moved: // A segment is moved
                                // Fix processor dependent address sensitive information
      // {
      //   ea_t from           = va_arg(va, ea_t);
      //   ea_t to             = va_arg(va, ea_t);
      //   asize_t size        = va_arg(va, asize_t);
      //   bool changed_netmap = va_argi(va, bool);
      //   // adjust gp_ea
      // }
      break;

    default:
      break;
  }
  return 0;
}

//----------------------------------------------------------------------
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_to_notification_point(HT_IDB, idb_callback);
      inf.set_be(false);
      prog_pointers.create("$ prog pointers");
      break;

    case processor_t::ev_is_sane_insn:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        int no_crefs = va_arg(va, int);
        code = nec850_is_sane_insn(insn, no_crefs) == 1 ? 1 : -1;
        break;
      }

    case processor_t::ev_newprc:
      {
        int procnum = va_arg(va, int);
        // bool keep_cfg = va_argi(va, bool);
        is_v850e = procnum == 0;
        break;
      }
    case processor_t::ev_term:
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    // old file loaded
    case processor_t::ev_oldfile:
      g_gp_ea = node2ea(prog_pointers.altval(GP_EA_IDX));
      g_ctbp_ea = node2ea(prog_pointers.altval(CTBP_EA_IDX));
      break;

    case processor_t::ev_creating_segm:
      {
        segment_t *s = va_arg(va, segment_t *);
        // Set default value of DS register for all segments
        set_default_dataseg(s->sel);
      }
      break;

    case processor_t::ev_may_be_func:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        code = nec850_may_be_func(insn);
      }
      break;

    case processor_t::ev_is_ret_insn:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        bool strict = va_argi(va, bool);
        code = nec850_is_return(insn, strict) ? 1 : -1;
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        nec850_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        nec850_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        nec850_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        nec850_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return nec850_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return nec850_emu(*insn) ? 1 : -1;
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

    case processor_t::ev_realcvt:
      {
        void *m = va_arg(va, void *);
        uint16 *e = va_arg(va, uint16 *);
        uint16 swt = va_argi(va, uint16);
        int code1 = ieee_realcvt(m, e, swt);
        return code1 == 0 ? 1 : code1;
      }

    case processor_t::ev_is_switch:
      {
        switch_info_t *si = va_arg(va, switch_info_t *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return nec850_is_switch(si, *insn) ? 1 : 0;
      }

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = nec850_is_sp_based(*insn, *op);
        return 1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        nec850_create_func_frame(pfn);
        return 1;
      }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        const func_t *pfn = va_arg(va, const func_t *);
        *frsize = nec850_get_frame_retsize(pfn);
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

//-----------------------------------------------------------------------
//      Registers Definition
//-----------------------------------------------------------------------
const char *RegNames[rLastRegister] =
{
  "r0",
  "r1",
  "r2",
  "sp",
  "gp",
  "r5", // text pointer - tp
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "r16",
  "r17",
  "r18",
  "r19",
  "r20",
  "r21",
  "r22",
  "r23",
  "r24",
  "r25",
  "r26",
  "r27",
  "r28",
  "r29",
  "ep",
  "lp",
  // system registers start here
  "eipc",
  "eipsw",
  "fepc",
  "fepsw",
  "ecr",
  "psw",
  "sr6",
  "sr7",
  "sr8",
  "sr9",
  "sr10",
  "sr11",
  "sr12",
  "sr13",
  "sr14",
  "sr15",
  "sr16",
  "sr17",
  "sr18",
  "sr19",
  "sr20",
  "sr21",
  "sr22",
  "sr23",
  "sr24",
  "sr25",
  "sr26",
  "sr27",
  "sr28",
  "sr29",
  "sr30",
  "sr31",
  //
  "ep", "cs", "ds"
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_NEC_V850X,         // id
                          // flag
    PR_DEFSEG32
  | PR_USE32
  | PRN_HEX
  | PR_RNAMESOK
  | PR_NO_SEGMOVE,
                          // flag2
    PR2_REALCVT           // the module has 'realcvt' event implementation
  | PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,                   // short processor names
  lnames,                    // long processor names

  asms,                      // assemblers

  notify,

  RegNames,                  // Regsiter names
  rLastRegister,             // Number of registers

  rVcs/*rVep*/,              // number of first segment register
  rVds/*rVcs*/,              // number of last segment register
  0 /*4*/,                   // size of a segment register
  rVcs,
  rVds,
  NULL,                      // No known code start sequences
  NULL,                      // Array of 'return' instruction opcodes
  NEC850_NULL,
  NEC850_LAST_INSTRUCTION,
  Instructions,                 // instruc
  0,                         // size of tbyte
  {0,7,15,0},                // real width
  0,                         // icode_return
  NULL,                      // Micro virtual machine description
};
