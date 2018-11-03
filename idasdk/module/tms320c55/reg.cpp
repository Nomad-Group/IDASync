/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ctype.h>
#include "tms320c55.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <ieee.h>

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "AC0",    // Accumulator
  "AC1",    // Accumulator
  "AC2",    // Accumulator
  "AC3",    // Accumulator
  "T0",     // Temporary register
  "T1",     // Temporary register
  "T2",     // Temporary register
  "T3",     // Temporary register
  "AR0",    // Auxiliary register
  "AR1",    // Auxiliary register
  "AR2",    // Auxiliary register
  "AR3",    // Auxiliary register
  "AR4",    // Auxiliary register
  "AR5",    // Auxiliary register
  "AR6",    // Auxiliary register
  "AR7",    // Auxiliary register

  "AC0L",   // Accumulator
  "AC0H",   // Accumulator
  "AC0G",   // Accumulator
  "AC1L",   // Accumulator
  "AC1H",   // Accumulator
  "AC1G",   // Accumulator
  "AC2L",   // Accumulator
  "AC2H",   // Accumulator
  "AC2G",   // Accumulator
  "AC3L",   // Accumulator
  "AC3H",   // Accumulator
  "AC3G",   // Accumulator
  "BK03",   // Circular buffer size register
  "BK47",   // Circular buffer size register
  "BKC",    // Circular buffer size register
  "BRC0",   // Block-repeat counter
  "BRC1",   // Block-repeat counter
  "BRS1",   // BRC1 save register
  "BSA01",  // Circulat buffer start address register
  "BSA23",  // Circulat buffer start address register
  "BSA45",  // Circulat buffer start address register
  "BSA67",  // Circulat buffer start address register
  "BSAC",   // Circulat buffer start address register
  "CDP",    // Coefficient data pointer (low part of XCDP)
  "CDPH",   // High part of XCDP
  "CFCT",   // Control-flow contect register
  "CSR",    // Computed single-repeat register
  "DBIER0", // Debug interrupt enable register
  "DBIER1", // Debug interrupt enable register
  // DP        Data page register (low part of XDP)
  // DPH       High part of XDP
  "IER0",   // Interrupt enable register
  "IER1",   // Interrupt enable register
  "IFR0",   // Interrupt flag register
  "IFR1",   // Interrupt flag register
  "IVPD",
  "IVPH",
  "PC",     // Program counter
  // PDP       Peripheral data page register
  "PMST",
  "REA0",   // Block-repeat end address register
  "REA0L",  // Block-repeat end address register
  "REA0H",  // Block-repeat end address register
  "REA1",   // Block-repeat end address register
  "REA1L",  // Block-repeat end address register
  "REA1H",  // Block-repeat end address register
  "RETA",   // Return address register
  "RPTC",   // Single-repeat counter
  "RSA0",   // Block-repeat start address register
  "RSA0L",  // Block-repeat start address register
  "RSA0H",  // Block-repeat start address register
  "RSA1",   // Block-repeat start address register
  "RSA1L",  // Block-repeat start address register
  "RSA1H",  // Block-repeat start address register
  "SP",     // Data stack pointer
  "SPH",    // High part of XSP and XSSP
  "SSP",    // System stack pointer
  "ST0",    // Status register
  "ST1",    // Status register
  "ST0_55", // Status register
  "ST1_55", // Status register
  "ST2_55", // Status register
  "ST3_55", // Status register
  "TRN0",   // Transition register
  "TRN1",   // Transition register

  "XAR0",   // Extended auxiliary register
  "XAR1",   // Extended auxiliary register
  "XAR2",   // Extended auxiliary register
  "XAR3",   // Extended auxiliary register
  "XAR4",   // Extended auxiliary register
  "XAR5",   // Extended auxiliary register
  "XAR6",   // Extended auxiliary register
  "XAR7",   // Extended auxiliary register

  "XCDP",   // Extended coefficient data pointer
  "XDP",    // Extended data page register
  "XPC",    // Extended program counter
  "XSP",    // Extended data stack pointer
  "XSSP",   // Extended system stack pointer

  "MDP",    // Main Data page pointer (direct memory access / indirect from CDP)
  "MDP05",  // Main Data page pointer (indirect AR[0-5])
  "MDP67",  // Main Data page pointer (indirect AR[6-7])

  // flags
  "ACOV2",
  "ACOV3",
  "TC1",
  "TC2",
  "CARRY",
  "ACOV0",
  "ACOV1",
  "BRAF",
  "XF",
  "HM",
  "INTM",
  "M40",
  "SATD",
  "SXMD",
  "C16",
  "FRCT",
  "C54CM",
  "DBGM",
  "EALLOW",
  "RDM",
  "CDPLC",
  "AR7LC",
  "AR6LC",
  "AR5LC",
  "AR4LC",
  "AR3LC",
  "AR2LC",
  "AR1LC",
  "AR0LC",
  "CAFRZ",
  "CAEN",
  "CACLR",
  "HINT",
  "CBERR",
  "MPNMC",
  "SATA",
  "CLKOFF",
  "SMUL",
  "SST",

  "BORROW",

  // segment registers
  "ARMS",   // AR indirect operands available
  "CPL",    // Compiler mode
  "DP",     // Data page pointer
  "DPH",    // Data page
  "PDP",    // Peripheral data page register
  "cs","ds" // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x48, 0x04 }; // ret
static const uchar retcode_1[] = { 0x48, 0x05 }; // reti

static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      TMS320C55 ASM
//-----------------------------------------------------------------------
static const asm_t masm55 =
{
  AS_COLON|AS_N2CHR|ASH_HEXF0|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP,
  0,
  "MASM55",
  0,
  NULL,         // header lines
  NULL,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  "MY_BYTE",    // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space 8*%s",// uninited arrays
  ".asg",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  NULL,         // "weak"   name keyword
  ".ref",       // "extrn"  name keyword
  NULL,         // "comm" (communal variable)
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
  NULL,         // sizeof
  AS2_STRINV    // invert string byte order
};

static const asm_t *const asms[] = { &masm55, NULL };

//--------------------------------------------------------------------------
static ioports_t ports;
static qstring device;
static const char *const cfgname = "tms320c55.cfg";

static void load_symbols(void)
{
  ports.clear();
  read_ioports(&ports, &device, cfgname);
}

const char *find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ports, address);
  return port ? port->name.c_str() : NULL;
}

//--------------------------------------------------------------------------
inline void set_device_name(const char *dev)
{
  if ( dev != NULL )
    device = dev;
}

//--------------------------------------------------------------------------
static int idaapi choose_device(int, form_actions_t &)
{
  if ( choose_ioport_device(&device, cfgname) )
    load_symbols();
  return 0;
}

static const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  if ( keyword == NULL )
  {
    static const char form[] =
"HELP\n"
"TMS320C55 specific options\n"
"\n"
" Use I/O definitions \n"
"\n"
"       If this option is on, IDA will use I/O definitions\n"
"       from the configuration file into a macro instruction.\n"
"\n"
" Detect memory mapped registers \n"
"\n"
"       If this option is on, IDA will replace addresses\n"
"       by an equivalent memory mapped register.\n"
"\n"
"ENDHELP\n"
"TMS320C54 specific options\n"
"\n"
" <Use ~I~/O definitions:C>\n"
" <Detect memory mapped ~r~egisters:C>>\n"
"\n"
" <~C~hoose device name:B:0::>\n"
"\n"
"\n";
    ask_form(form, &idpflags, choose_device);
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "TMS320C55_IO") == 0 )
    {
      setflag(idpflags, TMS320C55_IO, *(int*)value != 0);
      return IDPOPT_OK;
    }
    else if ( strcmp(keyword, "TMS320C55_MMR") == 0 )
    {
      setflag(idpflags, TMS320C55_MMR, *(int*)value != 0);
      return IDPOPT_OK;
    }
    return IDPOPT_BADKEY;
  }
}

//--------------------------------------------------------------------------

netnode helper;
proctype_t ptype = TMS320C55;
ushort idpflags = TMS320C55_IO|TMS320C55_MMR;

static const proctype_t ptypes[] =
{
  TMS320C55
};

//--------------------------------------------------------------------------
static ssize_t idaapi idb_callback(void *, int code, va_list /*va*/)
{
  switch ( code )
  {
    case idb_event::closebase:
    case idb_event::savebase:
      helper.altset(-1, idpflags);
      helper.supset(0,  device.c_str());
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_to_notification_point(HT_IDB, idb_callback);
      helper.create("$ tms320c54");
      if ( helper.supstr(&device, 0) > 0 )
        set_device_name(device.c_str());
      inf.set_be(true); // MSB first
      break;

    case processor_t::ev_term:
      ports.clear();
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    case processor_t::ev_newfile:   // new file loaded
      {
        {
          set_default_sreg_value(NULL, ARMS, 0);
          set_default_sreg_value(NULL, CPL, 1);
          for ( int i = DP; i <= rVds; i++ )
            set_default_sreg_value(NULL, i, 0);
        }
        static const char *const informations =
          "AUTOHIDE REGISTRY\n"
          "Default values of flags and registers:\n"
          "\n"
          "ARMS bit = 0 (DSP mode operands).\n"
          "CPL  bit = 1 (SP direct addressing mode).\n"
          "DP register = 0 (Data Page register)\n"
          "DPH register = 0 (High part of EXTENDED Data Page Register)\n"
          "PDP register = 0 (Peripheral Data Page register)\n"
          "\n"
          "You can change the register values by pressing Alt-G\n"
          "(Edit, Segments, Change segment register value)\n";
        info(informations);
        break;
      }

    case processor_t::ev_oldfile:   // old file loaded
      idpflags = (ushort)helper.altval(-1);
      break;

    case processor_t::ev_newprc:    // new processor type
      {
        ptype = ptypes[va_arg(va, int)];
        // bool keep_cfg = va_argi(va, bool);
        switch ( ptype )
        {
          case TMS320C55:
            break;
          default:
            error("interr: setprc");
            break;
        }
        device.qclear();
        load_symbols();
      }
      break;

    case processor_t::ev_newasm:    // new assembler type
      break;

    case processor_t::ev_creating_segm:    // new segment
      break;

    case processor_t::ev_get_stkvar_scale_factor:
      return 2;

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        assumes(*ctx);
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

    case processor_t::ev_can_have_type:
      {
        const op_t *op = va_arg(va, const op_t *);
        return can_have_type(*op) ? 1 : -1;
      }

    case processor_t::ev_realcvt:
      {
        void *m = va_arg(va, void *);
        uint16 *e = va_arg(va, uint16 *);
        uint16 swt = va_argi(va, uint16);
        int code1 = ieee_realcvt(m, e, swt);
        return code1 == 0 ? 1 : code1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
        return 1;
      }

    case processor_t::ev_gen_stkvar_def:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const member_t *mptr = va_arg(va, const member_t *);
        sval_t v = va_arg(va, sval_t);
        gen_stkvar_def(*ctx, mptr, v);
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
#define FAMILY "TMS320C55x Series:"
static const char *const shnames[] =
{ "TMS32055",
  NULL
};
static const char *const lnames[] =
{
  FAMILY"Texas Instruments TMS320C55",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_TMS320C55,         // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER
  | PR_SCALE_STKVARS,
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

  ARMS,                 // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  TMS320C55_null,
  TMS320C55_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0,7,15,19 },        // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  TMS320C55_ret,        // Icode of return instruction. It is ok to give any of possible return instructions
};
