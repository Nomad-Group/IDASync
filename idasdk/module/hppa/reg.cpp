/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "hppa.hpp"
#include "hppa_cfh.cpp"
#include <diskio.hpp>
#include <typeinf.hpp>

#include <ieee.h>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  // general registers (r0 is always 0)
  // r31 is for BLE instruction
  "%r0",  "%r1",  "%rp",  "%r3",  "%r4",  "%r5",  "%r6",  "%r7",
  "%r8",  "%r9",  "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
  "%r16", "%r17", "%r18", "%r19", "%r20", "%r21", "%r22", "%r23",
  "%r24", "%r25", "%r26", "%dp",  "%r28", "%r29", "%sp",  "%r31",
  // space registers
  "%sr0", "%sr1", "%sr2", "%sr3", "%sr4", "%sr5", "%sr6", "%sr7",
  // control registers
  "%rctr", "%cr1",   "%cr2",  "%cr3",  "%cr4",   "%cr5",  "%cr6",  "%cr7",
  "%pidr1","%pidr2", "%ccr",  "%sar",  "%pidr3", "%pidr4","%iva",  "%eiem",
  "%itmr", "%pcsq",  "pcoq",  "%iir",  "%isr",   "%ior",  "%ipsw", "%eirr",
  "%tr0",  "%tr1",   "%tr2",  "%tr3",  "%tr4",   "%tr5",  "%tr6",  "%tr7",
  // floating-point registers
  "%fpsr", "%fr1",  "%fr2",  "%fr3",  "%fr4",  "%fr5",  "%fr6",  "%fr7",
  "%fr8",  "%fr9",  "%fr10", "%fr11", "%fr12", "%fr13", "%fr14", "%fr15",
  "%fr16", "%fr17", "%fr18", "%fr19", "%fr20", "%fr21", "%fr22", "%fr23",
  "%fr24", "%fr25", "%fr26", "%fr27", "%fr28", "%fr29", "%fr30", "%fr31",
  // register halves
  "%fr16l", "%fr17l", "%fr18l", "%fr19l", "%fr20l", "%fr21l", "%fr22l", "%fr23l",
  "%fr24l", "%fr25l", "%fr26l", "%fr27l", "%fr28l", "%fr29l", "%fr30l", "%fr31l",
  "%fr16r", "%fr17r", "%fr18r", "%fr19r", "%fr20r", "%fr21r", "%fr22r", "%fr23r",
  "%fr24r", "%fr25r", "%fr26r", "%fr27r", "%fr28r", "%fr29r", "%fr30r", "%fr31r",
  // condition bits
  "%ca0", "%ca1", "%ca2", "%ca3", "%ca4", "%ca5", "%ca6",

  "dp",            // segment register to represent DP
  "cs","ds",       // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0xE8, 0x40, 0xC0, 0x00 };  // bv %r0(%rp)

static const bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gas =
{
  AS_ASCIIC|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU-like hypothetical assembler",
  0,
  NULL,         // header lines
  ".org",       // org
  NULL,         // end

  "#",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".string",    // ascii string directive
  ".byte",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  ".quad",      // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  ".ds.#s(b,w,l,d) #d, #v", // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  ".",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  NULL,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "mod",        // mod
  "and",        // and
  "or",         // or
  "xor",        // xor
  "not",        // not
  "shl",        // shl
  "shr",        // shr
  NULL,         // sizeof
  0,            // flag2
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
  NULL,         // vstruc_fmt
  NULL,         // rva
};

static const asm_t *const asms[] = { &gas, NULL };

//--------------------------------------------------------------------------
netnode helper;

//--------------------------------------------------------------------------
static void setup_got(void)
{
  got = get_gotea();
  if ( got == BADADDR )
    get_name_value(&got, BADADDR, "_GLOBAL_OFFSET_TABLE_");
  if ( got == BADADDR )
  {
    segment_t *s = get_segm_by_name(".got");
    if ( s != NULL )
      got = s->start_ea;
  }
  msg("DP is assumed to be %08a\n", got);
}

//--------------------------------------------------------------------------
static void handle_new_flags(void)
{
  if ( mnemonic() )
  {
    register_names[26] = "%arg0";
    register_names[25] = "%arg1";
    register_names[24] = "%arg2";
    register_names[23] = "%arg3";
    register_names[28] = "%ret0";
  }
  else
  {
    register_names[26] = "%r26";
    register_names[25] = "%r25";
    register_names[24] = "%r24";
    register_names[23] = "%r23";
    register_names[28] = "%r28";
  }
}

//--------------------------------------------------------------------------
static ioports_t syscalls;

const char *get_syscall_name(int syscall)
{
  const ioport_t *p = find_ioport(syscalls, syscall);
  return p == NULL ? NULL : p->name.c_str();
}

//--------------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  static const char form[] =
    "HELP\n"
    "HP PA-RISC specific options\n"
    "\n"
    " Simplify instructions\n"
    "\n"
    "       If this option is on, IDA will simplify instructions and replace\n"
    "       them by clearer pseudo-instructions\n"
    "       For example,\n"
    "\n"
    "               or      0, 0, 0\n"
    "\n"
    "       will be replaced by\n"
    "\n"
    "               nop\n"
    "\n"
    " PSW bit W is on\n"
    "\n"
    "       If this option is on, IDA will disassemble instructions as if\n"
    "       PSW W bit is on, i.e. addresses are treated as 64bit. In fact,\n"
    "       IDA still will truncate them to 32 bit, but this option changes\n"
    "       disassembly of load/store instructions.\n"
    "\n"
    " Use mnemonic register names\n"
    "\n"
    "       If checked, IDA will use mnemonic names of the registers:\n"
    "         %r26:  %arg0\n"
    "         %r25:  %arg1\n"
    "         %r24:  %arg2\n"
    "         %r23:  %arg3\n"
    "         %r28:  %ret0\n"
    "\n"
    "\n"
    "ENDHELP\n"
    "HPPA specific options\n"
    "\n"
    " <~S~implify instructions:C>\n"
    " <PSW bit W is on (for 64-bit):C>\n"
    " <Use ~m~nemonic register names:C>>\n"
    "\n"
    "\n";

  if ( keyword == NULL )
  {
    ask_form(form, &idpflags);
OK:
    helper.altset(-1, idpflags);
    handle_new_flags();
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "HPPA_SIMPLIFY") == 0 )
    {
      setflag(idpflags, IDP_SIMPLIFY, *(int*)value != 0);
      goto OK;
    }
    if ( strcmp(keyword, "HPPA_MNEMONIC") == 0 )
    {
      setflag(idpflags, IDP_MNEMONIC, *(int*)value != 0);
      goto OK;
    }
    if ( strcmp(keyword, "HPPA_PSW_W") == 0 )
    {
      setflag(idpflags,IDP_PSW_W,*(int*)value != 0);
      goto OK;
    }
    return IDPOPT_BADKEY;
  }
}

//--------------------------------------------------------------------------

int ptype;
ea_t got = BADADDR;

ushort idpflags = IDP_SIMPLIFY;

static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
//      __emit__(0xCC);   // debugger trap
      helper.create("$ hppa");
      inf.set_be(true);         // always big endian
      read_ioports(&syscalls, NULL, "hpux.cfg");
      init_custom_refs();
      break;

    case processor_t::ev_term:
      term_custom_refs();
      syscalls.clear();
      break;

    case processor_t::ev_newfile:      // new file loaded
      handle_new_flags();
      setup_got();
      break;

    case processor_t::ev_oldfile:      // old file loaded
      idpflags = ushort(helper.altval(-1));
      handle_new_flags();
      setup_got();
      break;

    case processor_t::ev_newprc:    // new processor type
      break;

    case processor_t::ev_newasm:    // new assembler type
      break;

    case processor_t::ev_creating_segm:    // new segment
      {
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[ rVds-ph.reg_first_sreg] = find_selector(sptr->sel);
        sptr->defsr[DPSEG-ph.reg_first_sreg] = 0;
      }
      break;

    case processor_t::ev_is_sane_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        int nocrefs = va_arg(va, int);
        return is_sane_insn(*insn, nocrefs) == 1 ? 1 : -1;
      }

    case processor_t::ev_may_be_func:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return may_be_func(*insn);
      }

    case processor_t::ev_is_basic_block_end:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return is_basic_block_end(*insn) ? 1 : -1;
      }

// +++ TYPE CALLBACKS (only 32-bit programs for the moment)
    case processor_t::ev_decorate_name:
      {
        qstring *outbuf  = va_arg(va, qstring *);
        const char *name = va_arg(va, const char *);
        bool mangle      = va_argi(va, bool);
        cm_t cc          = va_argi(va, cm_t);
        tinfo_t *type    = va_arg(va, tinfo_t *);
        return gen_decorate_name(outbuf, name, mangle, cc, type) ? 1 : 0;
      }

    case processor_t::ev_max_ptr_size:
      return 4;

    case processor_t::ev_get_default_enum_size: // get default enum size
                                // args:  cm_t cm
                                // returns: sizeof(enum)
      {
//        cm_t cm        =  va_argi(va, cm_t);
        return inf.cc.size_e;
      }

    case processor_t::ev_calc_arglocs:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        return calc_hppa_arglocs(fti) ? 1 : -1;
      }

    case processor_t::ev_use_stkarg_type:
        return 0;

    case processor_t::ev_use_regarg_type:
      {
        int *used                 = va_arg(va, int *);
        ea_t ea                   = va_arg(va, ea_t);
        const funcargvec_t *rargs = va_arg(va, const funcargvec_t *);
        *used = use_hppa_regarg_type(ea, *rargs);
        return 1;
      }

    case processor_t::ev_use_arg_types:
      {
        ea_t ea               = va_arg(va, ea_t);
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        funcargvec_t *rargs   = va_arg(va, funcargvec_t *);
        use_hppa_arg_types(ea, fti, rargs);
        return 1;
      }

    case processor_t::ev_get_cc_regs:
      {
        callregs_t *callregs = va_arg(va, callregs_t *);
        cm_t cc = va_argi(va, cm_t);
        static const int fastcall_regs[] = { R26, R25, R24, R23, -1 };
        if ( cc == CM_CC_FASTCALL )
          callregs->set(ARGREGS_INDEPENDENT, fastcall_regs, NULL);
        else if ( cc == CM_CC_THISCALL )
          callregs->reset();
        else
          break;
        return 1;
      }

    case processor_t::ev_calc_cdecl_purged_bytes:
                                // calculate number of purged bytes after call
      {
        // ea_t ea                     = va_arg(va, ea_t);
        return 0;
      }

    case processor_t::ev_get_stkarg_offset:
                                // get offset from SP to the first stack argument
                                // args: none
                                // returns: the offset+2
      return -0x34;

// --- TYPE CALLBACKS

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        hppa_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        hppa_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        hppa_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        hppa_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        hppa_assumes(*ctx);
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
        int code1 = ieee_realcvt(m, e, swt);
        return code1 == 0 ? 1 : code1;
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
        *frsize = hppa_get_frame_retsize(pfn);
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

    case processor_t::ev_is_align_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        return is_align_insn(ea);
      }

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
static const char *const shnames[] = { "hppa", NULL };
static const char *const lnames[] =
{
  "PA-RISC",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_HPPA,              // id
                          // flag
    PRN_HEX               // hex numbers
  | PR_ALIGN              // data items should be aligned
  | PR_DEFSEG32           // 32-bit segments by default
  | PR_SEGS               // has segment registers
  | PR_SGROTHER           // segment register mean something unknown to the kernel
  | PR_STACK_UP           // stack grows up
  | PR_TYPEINFO           // type system is supported
  | PR_USE_ARG_TYPES      // use ph.use_arg_types()
  | PR_DELAYED,           // has delayed jumps and calls
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

  DPSEG,                // first
  rVds,                 // last
  8,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  HPPA_null,
  HPPA_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  HPPA_rfi,             // Icode of return instruction. It is ok to give any of possible return instructions
};
