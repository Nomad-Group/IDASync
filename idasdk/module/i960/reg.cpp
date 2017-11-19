/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "i960.hpp"
#include <diskio.hpp>
#include <typeinf.hpp>
#include <ieee.h>

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "pfp", "sp", "rip", "r3",  "r4",  "r5",  "r6",  "r7",
  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  "g0",  "g1", "g2",  "g3",  "g4",  "g5",  "g6",  "g7",
  "g8",  "g9", "g10", "g11", "g12", "g13", "g14", "fp",
  "sf0",  "sf1", "sf2",  "sf3",  "sf4",  "sf5",  "sf6",  "sf7",
  "sf8",  "sf9", "sf10", "sf11", "sf12", "sf13", "sf14", "sf15",
  "sf16", "sf17","sf18", "sf19", "sf20", "sf21", "sf22", "sf23",
  "sf24", "sf25","sf26", "sf27", "sf28", "sf29", "sf30", "sf31",
  "pc",   "ac",  "ip",   "tc",
  "fp0",  "fp1", "fp2",  "fp3",
  "ds", "cs",
};

//--------------------------------------------------------------------------
static const bytes_t retcodes[] =
{
// { sizeof(retcode0), retcode0 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      GNU assembler
//-----------------------------------------------------------------------
static const asm_t gnuasm =
{
  AS_ASCIIC|AS_ALIGN2|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU assembler",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  ".org",       // org
  NULL,         // end

  "#",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  ".quad",      // qwords
  ".octa",      // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  ".extended",  // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  ".fill #d, #s(1,2,4,8), #v", // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
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
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
};

static const asm_t *const asms[] = { &gnuasm, NULL };

//--------------------------------------------------------------------------
netnode helper;
ushort idpflags = IDP_STRICT;
static ioport_t *ports = NULL;
static size_t numports = 0;
static char device[MAXSTR] = "";
static const char *const cfgname = "i960.cfg";

static void load_symbols(void)
{
  free_ioports(ports, numports);
  ports = read_ioports(&numports, cfgname, device, sizeof(device), NULL);
}

const char *find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? port->name : NULL;
}


//--------------------------------------------------------------------------
inline void set_device_name(const char *dev)
{
  if ( dev != NULL )
    qstrncpy(device, dev, sizeof(device));
}

static void idaapi choose_device(TView *[],int)
{
  if ( choose_ioport_device(cfgname, device, sizeof(device), NULL) )
  {
    load_symbols();
  }
}

static const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  static const char form[] =
    "HELP\n"
    "Intel 960 specific options\n"
    "\n"
    " Choose device name\n"
    "       Here you may select a specific Intel 960 device\n"
    "       IDA will use the definitions in the I960.CFG file for\n"
    "       the i/o port names\n"
    "\n"
    " Strictly adhere to instruction encodings\n"
    "       If this option is on, IDA will check that unused fields\n"
    "       of instructions are filled by zeroes. If they are not,\n"
    "       it will refuse to disassemble the instruction.\n"
    "\n"
    "ENDHELP\n"
    "Intel 960 specific options\n"
    "\n"
    " <~C~hoose device name:B:0:::>\n"
    "\n"
    " <~S~trictly adhere to instruction encodings:C>>\n"
    "\n"
    "\n";

  if ( keyword == NULL )
  {
    AskUsingForm_c(form, choose_device, &idpflags);
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "I960_STRICT") == 0 )
    {
      setflag(idpflags, IDP_STRICT, *(int*)value != 0);
      return IDPOPT_OK;
    }
  }
  return IDPOPT_BADKEY;
}

//--------------------------------------------------------------------------
static int idaapi notify(processor_t::idp_notify msgid, ...)
{
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  switch ( msgid )
  {
    case processor_t::init:
      helper.create("$ i960");
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::closebase:
    case processor_t::savebase:
      helper.supset(0,  device);
      helper.altset(-1, idpflags);
      break;

    case processor_t::newfile:   // new file loaded
      choose_device(NULL, 0);
      break;

    case processor_t::oldfile:   // old file loaded
      idpflags = helper.altval(-1);
      break;

    case processor_t::newprc:
      {
        int n = va_arg(va, int);
        inf.mf = (n > 1);
        char buf[MAXSTR];
        if ( helper.supval(0, buf, sizeof(buf)) > 0 )
          set_device_name(buf);
        load_symbols();
      }
      break;

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
        /*unsigned int ptrt =*/ va_arg(va, unsigned int);
        char **ptrname    = va_arg(va, char **);
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
      return -1;

    case processor_t::use_stkarg_type3:
      return -1;

    case processor_t::use_regarg_type3:
      return -1;

    case processor_t::get_fastcall_regs3:
    case processor_t::get_thiscall_regs3:
      {
        callregs_t *callregs = va_arg(va, callregs_t *);
        callregs->reset();
        return 2;
      }

    case processor_t::calc_cdecl_purged_bytes2:// calculate number of purged bytes after call
      {
        // ea_t ea                     = va_arg(va, ea_t);
        return 2;
      }

    case processor_t::get_stkarg_offset2:  // get offset from SP to the first stack argument
                                // args: none
                                // returns: the offset
      return 2;

// --- TYPE CALLBACKS

    default:
      return handle_old_type_callbacks(msgid, va);
  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
#define FAMILY "Intel 960:"

static const char *const shnames[] =
{
  "i960",
  "i960l",
  "i960b",
  NULL
};

static const char *const lnames[] =
{
  FAMILY"Intel 960 little endian (default)",
  "Intel 960 little endian",
  "Intel 960 big endian",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_I960,                    // id
  PRN_HEX|PR_RNAMESOK|PR_SEGS|PR_USE32|PR_DEFSEG32|PR_TYPEINFO|PR_TINFO,
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  segend,

  NULL,                 // generate "assume" directives

  ana,                  // analyze instruction
  emu,                  // emulate instruction

  out,                  // generate text representation of instruction
  outop,                // generate ...                    operand
  intel_data,           // generate ...                    data directive
  NULL,                 // compare operands
  NULL,                 // can have type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  ds,                   // first
  cs,                   // last
  2,                    // size of a segment register
  cs, ds,

  NULL,                 // No known code start sequences
  retcodes,

  I960_null,
  I960_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  10,                   // int tbyte_size (0-doesn't exist)
  ieee_realcvt,         // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 7, 15, 19 },     // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x);
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,sval_t v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  I960_ret,             // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
