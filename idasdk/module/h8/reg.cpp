/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@datarescue.com
 *
 */

#include "h8.hpp"
#include <diskio.hpp>
#include <frame.hpp>
#include <segregs.hpp>

#include <ieee.h>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
  "e0",   "e1",   "e2",  "e3",  "e4",  "e5",  "e6",  "e7",
  "r0h",  "r1h",  "r2h", "r3h", "r4h", "r5h", "r6h", "r7h",
  "r0l",  "r1l",  "r2l", "r3l", "r4l", "r5l", "r6l", "r7l",
  "er0",  "er1",  "er2", "er3", "er4", "er5", "er6", "er7",
  "macl", "mach",
  "pc",
  "ccr", "exr",
  "cs","ds",       // virtual registers for code and data segments
  "vbr", "sbr",
};

//--------------------------------------------------------------------------
static const uchar startcode_0[] = { 0x01, 0x00, 0x6D, 0xF3 };  // push.l  er3
static const uchar startcode_1[] = { 0x6D, 0xF3 };              // push.w  r3

static const bytes_t startcodes[] =
{
  { sizeof(startcode_0), startcode_0 },
  { sizeof(startcode_1), startcode_1 },
  { 0, NULL }
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gas =
{
  AS_ASCIIC|AS_ALIGN2|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU assembler",
  0,
  NULL,         // header lines
  ".org",       // org
  NULL,         // end

  ";",          // comment string
  '"',          // string delimiter
  '"',          // char delimiter
  "\"",         // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".globl",     // "public" name keyword
  NULL,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof_fmt
  0,            // flag2
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
  NULL,         // a_vstruc_fmt
  NULL,         // a_rva
  NULL,         // a_yword
};

//-----------------------------------------------------------------------
//      HEW ASM
//-----------------------------------------------------------------------
const asm_t hew =
{
  AS_ASCIIC|AS_ALIGN2|ASH_HEXF1|ASD_DECF0|ASO_OCTF7|ASB_BINF4|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  UAS_HEW,
  "HEW assembler",
  0,
  NULL,         // header lines
  ".org",       // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '"',          // char delimiter
  "\"",         // special symbols in char and string constants

  ".sdata",     // ascii string directive
  ".data.b",    // byte directive
  ".data.w",    // word directive
  ".data.l",    // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".res %s",    // uninited arrays
  ": .assign",  // equ that allows set/reset values
//": .equ",     // equ          (does not allow for reuse)
//": .reg (%s)",// equ for regs (does not allow for reuse)
//": .bequ",    // equ for bits (does not allow for reuse)
  NULL,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  NULL,         // "weak"   name keyword
  ".global",    // "extrn"  name keyword
  ".comm",      // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "~",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  "sizeof",     // sizeof_fmt
  0,            // flag2
  NULL,         // cmnt2
  "low",        // low8
  "high",       // high8
  "lword",      // low16
  "hword",      // high16
  ".include \"%s\"",  // a_include_fmt
  NULL,         // a_vstruc_fmt
  NULL,         // a_rva
  NULL,         // a_yword
};

static const asm_t *const asms[] = { &gas, &hew, NULL };

//--------------------------------------------------------------------------
static qstring device;
static ioports_t ports;
static const char cfgname[] = "h8.cfg";

static void load_symbols(void)
{
  ports.clear();
  read_ioports(&ports, &device, cfgname);
}

//--------------------------------------------------------------------------
const char *find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ports, address);
  return port ? port->name.c_str() : NULL;
}

//--------------------------------------------------------------------------
static const char *idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL )
    return IDPOPT_BADKEY;
  if ( choose_ioport_device(&device, cfgname) )
    load_symbols();
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
netnode helper;
proctype_t ptype;

static const proctype_t ptypes[] =
{
             P300,
  MODE_ADV | P300,
             P300 | P2000 | P2600,
  MODE_ADV | P300 | P2000 | P2600,
             P300 | P2000 | P2600 | PSX,
  MODE_MID | P300 | P2000 | P2600 | PSX,
  MODE_ADV | P300 | P2000 | P2600 | PSX,
  MODE_MAX | P300 | P2000 | P2600 | PSX,
};

//--------------------------------------------------------------------------
static ssize_t idaapi idb_callback(void *, int code, va_list /*va*/)
{
  switch ( code )
  {
    case idb_event::closebase:
    case idb_event::savebase:
      helper.supset(0, device.c_str());
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int ret = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
//      __emit__(0xCC);   // debugger trap
      hook_to_notification_point(HT_IDB, idb_callback);
      helper.create("$ h8");
      helper.supstr(&device, 0);
      inf.set_be(true);
      break;

    case processor_t::ev_term:
      ports.clear();
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    case processor_t::ev_newasm:    // new assembler type selected
      {
        int asmnum = va_arg(va, int);
        bool hew_asm = asmnum == 1;
        if ( advanced() )
        {
          register_names[R7]  = "r7";
          register_names[ER7] = hew_asm ? "er7" : "sp";
        }
        else
        {
          register_names[R7]  = hew_asm ? "r7" : "sp";
          register_names[ER7] = "er7";
        }
      }
      break;

    case processor_t::ev_newfile:   // new file loaded
      load_symbols();
      if ( is_h8sx() )
      {
        set_default_sreg_value(NULL, VBR, 0);
        set_default_sreg_value(NULL, SBR, 0xFFFFFF00);
      }
      break;

    case processor_t::ev_oldfile:   // old file loaded
      load_symbols();
      break;

    case processor_t::ev_newprc:    // new processor type
      ptype = ptypes[va_arg(va, int)];
      // bool keep_cfg = va_argi(va, bool);
      if ( advanced() )
      {
        ph.flag |= PR_DEFSEG32;
      }
      if ( is_h8sx() )
      {
        ph.flag |= PR_SEGS;
        ph.reg_last_sreg = SBR;
        ph.segreg_size = 4;
      }
      break;

    case processor_t::ev_creating_segm:    // new segment
      break;

    case processor_t::ev_is_jump_func:
      {
        const func_t *pfn = va_arg(va, const func_t *);
        ea_t *jump_target = va_arg(va, ea_t *);
        ret = is_jump_func(pfn, jump_target);
      }
      break;

    case processor_t::ev_is_sane_insn:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        int no_crefs = va_arg(va, int);
        ret = is_sane_insn(insn, no_crefs) == 1 ? 1 : -1;
      }
      break;

    case processor_t::ev_may_be_func:
                                // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        ret = may_be_func(insn);
      }
      break;

    case processor_t::ev_gen_regvar_def:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        regvar_t *v = va_arg(va, regvar_t*);
        if ( is_hew_asm() )
        {
          ctx->gen_printf(0,
                          COLSTR("%s", SCOLOR_REG)
                          COLSTR(": .reg (", SCOLOR_SYMBOL)
                          COLSTR("%s", SCOLOR_REG)
                          COLSTR(")", SCOLOR_SYMBOL),
                          v->user, v->canon);
          ret = 1;
        }
      }
      break;

    case processor_t::ev_is_ret_insn:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        ret = is_return_insn(insn) ? 1 : -1;
      }
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
        h8_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        h8_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        h8_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8_assumes(*ctx);
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

    case processor_t::ev_realcvt:
      {
        void *m = va_arg(va, void *);
        uint16 *e = va_arg(va, uint16 *);
        uint16 swt = va_argi(va, uint16);
        int code = ieee_realcvt(m, e, swt);
        return code == 0 ? 1 : code;
      }

    case processor_t::ev_is_switch:
      {
        switch_info_t *si = va_arg(va, switch_info_t *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return h8_is_switch(si, *insn) ? 1 : 0;
      }

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = is_sp_based(*insn, *op);
        return 1;
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
        *frsize = h8_get_frame_retsize(pfn);
        return 1;
      }

    case processor_t::ev_gen_stkvar_def:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const member_t *mptr = va_arg(va, const member_t *);
        sval_t v = va_arg(va, sval_t);
        h8_gen_stkvar_def(*ctx, mptr, v);
        return 1;
      }

    case processor_t::ev_set_idp_options:
      {
        const char *keyword = va_arg(va, const char *);
        int value_type = va_arg(va, int);
        const char *value = va_arg(va, const char *);
        const char *retstr = set_idp_options(keyword, value_type, value);
        if ( retstr == IDPOPT_OK )
          return 1;
        const char **errmsg = va_arg(va, const char **);
        if ( errmsg != NULL )
          *errmsg = retstr;
        return -1;
      }

    case processor_t::ev_is_align_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        return h8_is_align_insn(ea);
      }

    default:
      break;
  }
  return ret;
}

//-----------------------------------------------------------------------
#define FAMILY "Hitachi H8:"
static const char *const shnames[] =
{
  "h8300", "h8300a", "h8s300", "h8s300a", "h8sxn", "h8sxm", "h8sxa", "h8sx", NULL
};
static const char *const lnames[] =
{
  FAMILY"Hitachi H8/300H normal",
  "Hitachi H8/300H advanced",
  "Hitachi H8S normal",
  "Hitachi H8S advanced",
  "Hitachi H8SX normal",
  "Hitachi H8SX middle",
  "Hitachi H8SX advanced",
  "Hitachi H8SX maximum",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_H8,                // id
                          // flag
    PRN_HEX
  | PR_USE32
  | PR_WORD_INS,
                          // flag2
    PR2_REALCVT           // the module has 'realcvt' event implementation
  | PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  rVcs,                 // first
  rVds,                 // last
  0,                    // size of a segment register
  rVcs, rVds,

  startcodes,           // start sequences
  NULL,                 // see is_ret_insn callback in the notify() function

  H8_null,
  H8_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  H8_rts,               // Icode of return instruction. It is ok to give any of possible return instructions
};
