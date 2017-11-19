
/*
 *                      Interactive disassembler (IDA).
 *                      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                      ALL RIGHTS RESERVED.
 *                                                                                                                      E-mail: ig@estar.msk.su, ig@datarescue.com
 *                                                                                                                      FIDO:    2:5020/209
 *
 */

#include "arc.hpp"

//--------------------------------------------------------------------------
processor_subtype_t ptype;
netnode helper;
ushort idpflags = ARC_SIMPLIFY | ARC_INLINECONST | ARC_TRACKREGS;

static const char *const RegNames[] =
{
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",       // 0 .. 7
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", // 8 .. 15
  "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",       // 16 .. 23
  "r24", "r25", "gp", "fp", "sp", "ilink1", "ilink2", "blink",  // 23 .. 31

  "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",       // 31 .. 39
  "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",       // 40 .. 47
  "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",       // 48 .. 55
  "r56", "mlo", "mmid", "mhi","lp_count", "r61", "<limm>", "pcl",  // 56 .. 63
  // condition codes
  "CF", "ZF", "NF", "VF",
  "rVcs", "rVds"
};

static const uchar codeseq_arcompact[] = { 0xF1, 0xC0 };  // push blink
static const uchar codeseq_arctg4[]    = { 0x04, 0x3E, 0x0E, 0x10 }; // st blink, [sp,4]

static const bytes_t codestart_arcompact[] =
{
 { sizeof(codeseq_arcompact), codeseq_arcompact },
 { 0, NULL }
};

static const bytes_t codestart_arctg4[] =
{
 { sizeof(codeseq_arctg4), codeseq_arctg4 },
 { 0, NULL }
};

//----------------------------------------------------------------------
static void set_codeseqs()
{
  switch ( ptype )
  {
    case prc_arc:
      ph.codestart = codestart_arctg4;
      break;
    case prc_arcompact:
      ph.codestart = codestart_arcompact;
      break;
  }
}

//--------------------------------------------------------------------------
// handler for some IDB events
static int idaapi idb_notify(void *, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    case idb_event::op_type_changed:
      // An operand type (offset, hex, etc...) has been set or deleted
      {
        ea_t ea = va_arg(va, ea_t);
        int n = va_arg(va, int);
        if ( isCode(get_flags_novalue(ea)) )
        {
          insn_t saved = cmd;
          if ( ea != cmd.ea )
            decode_insn(ea);
          op_t& x = cmd.Operands[n];
          if ( x.type == o_mem )
          {
            ea = toEA(cmd.cs, x.addr);
            copy_insn_optype(x, ea, NULL, true);
          }
          cmd = saved;
        }
      }
      break;
  }
  return 0;
}

//----------------------------------------------------------------------
// The kernel event notifications
// Here you may take desired actions upon some kernel events
static int idaapi notify(processor_t::idp_notify msgid, ...)
{
  va_list va;

  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);

  if (code)
    return code;

  switch (msgid)
  {
    case processor_t::init:
      helper.create("$ arc");
      inf.mf = 0;               // Set little-endian mode of the IDA kernel
      set_codeseqs();
      hook_to_notification_point(HT_IDB, idb_notify, NULL);
      break;

    case processor_t::term:
      unhook_from_notification_point(HT_IDB, idb_notify, NULL);
      break;

    case processor_t::newfile:
      set_codeseqs();
      break;

    case processor_t::oldfile:
      idpflags = (ushort)helper.altval(-1);
      break;

    case processor_t::closebase:
    case processor_t::savebase:
      helper.altset(-1, idpflags);
      break;

    case processor_t::newseg:
      break;

    case processor_t::newprc:
      ptype = va_argi(va, processor_subtype_t);
      if ( uint(ptype) > prc_arcompact )
        return 0;
      set_codeseqs();
      break;

    case processor_t::is_call_insn:
                                // Is the instruction a "call"?
                                // ea_t ea  - instruction address
                                // returns: 1-unknown, 0-no, 2-yes
      {
        ea_t ea = va_arg(va, ea_t);
        insn_t saved = cmd;
        code = decode_insn(ea) != 0 && is_call_insn() ? 2 : 0;
        cmd = saved;
        return code;
      }

    case processor_t::is_ret_insn:
      {
        ea_t ea = va_arg(va, ea_t);
//        bool strict = va_argi(va, bool);
        insn_t saved = cmd;
        code = decode_insn(ea) != 0 && is_return_insn() ? 2 : 0;
        cmd = saved;
        return code;
      }

    case processor_t::is_basic_block_end:
      return is_basic_block_end() ? 2 : 0;

    case processor_t::undefine:
      {
        // an item is being undefined; delete data attached to it
        ea_t ea = va_arg(va, ea_t);
        del_insn_info(ea);
      }
      return 2;

// +++ TYPE CALLBACKS
    case processor_t::decorate_name3:
      {
        qstring *outbuf  = va_arg(va, qstring *);
        const char *name = va_arg(va, const char *);
        bool mangle      = va_argi(va, bool);
        cm_t cc          = va_argi(va, cm_t);
        return gen_decorate_name3(outbuf, name, mangle, cc) ? 2 : 0;
      }

    case processor_t::max_ptr_size:
      return 4+1;

    case processor_t::based_ptr:
      {
        uint ptrt      = va_arg(va, unsigned int); qnotused(ptrt);
        char **ptrname = va_arg(va, char **);
        *ptrname = NULL;
        return 0;                       // returns: size of type
      }

    case processor_t::get_default_enum_size: // get default enum size
                                // args:  cm_t cm
                                // returns: sizeof(enum)
      {
//        cm_t cm        =  va_argi(va, cm_t);
        return inf.cc.size_e;
      }

    case processor_t::calc_arglocs3:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        return calc_arc_arglocs(fti) ? 2 : -1;
      }

    case processor_t::calc_varglocs3:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        regobjs_t *regargs    = va_arg(va, regobjs_t *);
        /*relobj_t *stkargs =*/ va_arg(va, relobj_t *);
        int nfixed            = va_arg(va, int);
        return calc_arc_varglocs(fti, regargs, nfixed) ? 2 : -1;
      }

    case processor_t::calc_retloc3:
      {
        const tinfo_t *type = va_arg(va, const tinfo_t *);
        cm_t cc             = va_argi(va, cm_t);
        argloc_t *retloc    = va_arg(va, argloc_t *);
        return calc_arc_retloc(*type, cc, retloc) ? 2 : -1;
      }

    case processor_t::use_stkarg_type3:
      return false;

    case processor_t::use_regarg_type3:
      {
        int *used                 = va_arg(va, int *);
        ea_t ea                   = va_arg(va, ea_t);
        const funcargvec_t *rargs = va_arg(va, const funcargvec_t *);
        *used = use_arc_regarg_type(ea, *rargs);
        return 2;
      }

    case processor_t::use_arg_types3:
      {
        ea_t ea               = va_arg(va, ea_t);
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        funcargvec_t *rargs   = va_arg(va, funcargvec_t *);
        use_arc_arg_types(ea, fti, rargs);
        return 2;
      }

    case processor_t::get_fastcall_regs3:
    case processor_t::get_varcall_regs3:
      {
        const int *regs;
        get_arc_fastcall_regs(&regs);
        callregs_t *callregs = va_arg(va, callregs_t *);
        callregs->set(ARGREGS_INDEPENDENT, regs, NULL);
        return callregs->nregs + 2;
      }

    case processor_t::get_thiscall_regs3:
      {
        callregs_t *callregs = va_arg(va, callregs_t *);
        callregs->reset();
        return 2;
      }

    case processor_t::calc_cdecl_purged_bytes2:
                                // calculate number of purged bytes after call
      {
        // ea_t ea                     = va_arg(va, ea_t);
        return 2;
      }

    case processor_t::get_stkarg_offset2:
                                // get offset from SP to the first stack argument
                                // args: none
                                // returns: the offset+2
      return 2;

// --- TYPE CALLBACKS

    default:
      return handle_old_type_callbacks(msgid, va);
  }
  va_end(va);
  return 1;
}

static const ushort gnu_bad_insn[] = { ARC_flag, 0 };

//-----------------------------------------------------------------------
//                                                                       ASMI
//-----------------------------------------------------------------------
static const asm_t gnuas =
{
  AS_COLON | AS_N2CHR | AS_1TEXT | ASH_HEXF3 | ASO_OCTF1 | ASB_BINF3 |
    AS_ONEDUP | AS_ASCIIC,
  0,
  "GNU assembler",
  0,
  NULL,                         // no headers
  gnu_bad_insn,                 // GNU-as can't produce flag.f
  ".org",                       // org directive
  0,                            // end directive
  "#",                          // comment string
  '"',                          // string delimiter
  '\'',                         // char delimiter
  "\\\"'",                      // special symbols in char and string constants

  ".ascii",                     // ascii string directive
  ".byte",                      // byte directive
  ".short",                     // word directive
  ".long",                      // dword        (4 bytes)
  ".quad",                      // qword        (8 bytes)
  NULL,                         // oword        (16 bytes)
  ".float",                     // float        (4 bytes)
  ".double",                    // double (8 bytes)
  NULL,                         // tbyte        (10/12 bytes)
  NULL,                         // packed decimal real
  ".ds.#s(b,w,l,d) #d, #v",     // arrays (#h,#d,#v,#s(...)
  ".space %s",                  // uninited arrays
  "=",                          // equ
  NULL,                         // seg prefix
  NULL, NULL, NULL,
  NULL,                         // xlat ascii
  ".",                          // curent ip
  NULL,                         // func_header
  NULL,                         // func_footer
  ".global",                    // public
  NULL,                         // weak
  ".extern",                    // extrn
  ".comm",                      // comm
  NULL,                         // get_type_name
  ".align",                     // align
  '(', ')',                     // lbrace, rbrace
  "%",                          // mod
  "&",                          // and
  "|",                          // or
  "^",                          // xor
  "!",                          // not
  "<<",                         // shl
  ">>",                         // shr
  NULL,                         // sizeof
};


static const asm_t *const asms[] = { &gnuas, NULL };

static const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  if ( keyword == NULL )
  {
    static const char form[] =
"HELP\n"
"ARC specific options\n"
"\n"
" Simplify instructions\n"
"\n"
"      If this option is on, IDA will simplify instructions and replace\n"
"      them by more natural pseudo-instructions or alternative mnemonics.\n"
"      For example,\n"
"\n"
"                    sub.f   0, a, b\n"
"\n"
"     will be replaced by\n"
"\n"
"                    cmp a, b\n"
"\n"
"\n"
" Inline constant pool loads\n"
"\n"
"     If this option is on, IDA will use =label syntax for\n"
"     pc-relative loads (commonly used to load constants)\n"
"     For example,\n"
"\n"
"                   ld      r1, [pcl,0x1C]\n"
"                   ...\n"
"                   .long 0x2051D1C8\n"
"\n"
"     will be replaced by\n"
"\n"
"                   ld      r1, =0x2051D1C8\n"
"\n"
"\n"
" Track register accesses\n"
"\n"
"     This option tells IDA to track values loaded\n"
"     into registers and use it to improve the listing.\n"
"     For example,\n"
"\n"
"                   mov     r13, 0x172C\n"
"                   ...\n"
"                   add     r0, r13, 0x98\n"
"\n"
"     will be replaced by\n"
"\n"
"                   add     r0, r13, (dword_17C4 - 0x172C)\n"
"\n"
"\n"
"ENDHELP\n"
"ARC specific options\n"
"\n"
" <~S~implify instructions:C>\n"
" <~I~nline constant pool loads:C>\n"
" <Track ~r~egister accesses:C>>\n"
"\n"
"\n";
    AskUsingForm_c(form, &idpflags);
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "ARC_SIMPLIFY") == 0 )
    {
      setflag(idpflags, ARC_SIMPLIFY, *(int*)value != 0);
      return IDPOPT_OK;
    }
    else if ( strcmp(keyword, "ARC_INLINECONST") == 0 )
    {
      setflag(idpflags, ARC_INLINECONST, *(int*)value != 0);
      return IDPOPT_OK;
    }
    else if ( strcmp(keyword, "ARC_TRACKREGS") == 0 )
    {
      setflag(idpflags, ARC_TRACKREGS, *(int*)value != 0);
      return IDPOPT_OK;
    }
    return IDPOPT_BADKEY;
  }
}

//-----------------------------------------------------------------------
// The short and long names of the supported processors
#define FAMILY "Argonaut RISC Core:"

static const char *const shnames[] =
{
  "arc",
  "arcmpct",
  NULL
};

static const char *const lnames[] =
{
  FAMILY"Argonaut RISC Core ARCtangent-A4",
  "Argonaut RISC Core ARCompact",
  NULL
};

//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//                      - if an instruction has the "return" opcode, its autogenerated label
//                              will be "locret" rather than "loc".
//                      - IDA will use the first "return" opcode to create empty subroutines.

static const bytes_t retcodes[] =
{
  { 0, NULL }                    // NULL terminated array
};

//-----------------------------------------------------------------------
//                      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_ARC,                     // id
    PR_USE32            // 32-bit processor
  | PR_DEFSEG32         // create 32-bit segments by default
  | PRN_HEX             // Values are hexadecimal by default
  | PR_TYPEINFO | PR_TINFO // Support the type system notifications
  | PR_CNDINSNS         // Has conditional instructions
  | PR_DELAYED          // Has delay slots
  | PR_USE_ARG_TYPES    // use ph.use_arg_types callback
  | PR_RNAMESOK,        // register names can be reused for location names
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,                      // array of short processor names
  // the short names are used to specify the processor
  // with the -p command line switch)
  lnames,                       // array of long processor names
  // the long names are used to build the processor type
  // selection menu

  asms,                         // array of target assemblers

  notify,                       // the kernel event notification callback

  header,                       // generate the disassembly header
  footer,                       // generate the disassembly footer

  segstart,                     // generate a segment declaration (start of segment)
  std_gen_segm_footer,          // generate a segment footer (end of segment)

  NULL,                         // generate 'assume' directives

  ana,                          // analyze an instruction and fill the 'cmd' structure
  emu,                          // emulate an instruction

  out,                          // generate a text representation of an instruction
  outop,                        // generate a text representation of an operand
  intel_data,                   // generate a text representation of a data item
  NULL,                         // compare operands
  NULL,                         // can an operand have a type?

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Register names
  NULL,                         // get abstract register

  0,                            // Number of register files
  NULL,                         // Register file names
  NULL,                         // Register descriptions
  NULL,                         // Pointer to CPU registers

  rVcs,                         // first
  rVds,                         // last
  1,                            // size of a segment register
  rVcs, rVds,

  codestart_arcompact,          // code start sequences
  retcodes,

  0, ARC_last,
  Instructions,
  NULL,
  NULL,
  0,                            // size of tbyte
  NULL,
  {0},                          // real width
  NULL,
  NULL,                         // int32 (*gen_map_file)(FILE *fp);
  NULL,                         // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  is_sp_based,                  // is the operand based on SP register?
  create_func_frame,            // create frame of newly created function
  arc_get_frame_retsize,        // get function return size
  NULL,                         // generate declaration of stack variable
  gen_spcdef,                   // generate text for an item in a special segment
  0,                            // Icode of a return instruction
  set_idp_options,              // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,                // Is alignment instruction?
  NULL,                         // Micro virtual machine description
};
