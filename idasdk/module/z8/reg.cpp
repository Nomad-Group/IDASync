/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"
#include <diskio.hpp>

//--------------------------------------------------------------------------
ea_t intmem = BADADDR; // linear EA of the internal memory/registers segment

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  "R0",  "R1",  "R2",   "R3",   "R4",   "R5",   "R6",   "R7",
  "R8",  "R9",  "R10",  "R11",  "R12",  "R13",  "R14",  "R15",
  "RR0", "RR1", "RR2",  "RR3",  "RR4",  "RR5",  "RR6",  "RR7",
  "RR8", "RR9", "RR10", "RR11", "RR12", "RR13", "RR14", "RR15",
  "cs",  "ds",  "rp",
};

//----------------------------------------------------------------------
typedef struct
{
  int off;
  const char *name; //lint !e958 padding is required to align members
  const char *cmt;
} entry_t;

static const entry_t entries[] =
{
  {  0, "irq0", "DAV0, IRQ0, Comparator" },
  {  2, "irq1", "DAV1, IRQ1" },
  {  4, "irq2", "DAV2, IRQ2, TIN, Comparator" },
  {  6, "irq3", "IRQ3, Serial in" },
  {  8, "irq4", "T0, Serial out" },
  { 10, "irq5", "T1" },
};

netnode helper;
char device[MAXSTR] = "";
static size_t numports = 0;
static ioport_t *ports = NULL;

#define AREA_PROCESSING handle_area
static bool handle_area(ea_t start, ea_t end, const char *name, const char *aclass);
#include "../iocommon.cpp"

//------------------------------------------------------------------
const char *z8_find_ioport(uval_t port)
{
  const ioport_t *p = find_ioport(ports, numports, port);
  return p ? p->name : NULL;
}

//----------------------------------------------------------------------
static ea_t specialSeg(sel_t sel, bool make_imem = true)
{
  segment_t *s = get_segm_by_sel(sel);

  if ( s != NULL )
  {
    if ( make_imem && s->type != SEG_IMEM )
    {
      s->type = SEG_IMEM;
      s->update();
    }
    return s->startEA;
  }
  return BADADDR;
}

//----------------------------------------------------------------------
static void setup_data_segment_pointers(void)
{
  sel_t sel;
  if ( atos("INTMEM", &sel) || atos("RAM", &sel) )
    intmem = specialSeg(sel);
  else
    intmem = BADADDR;
}

//----------------------------------------------------------------------
static ea_t AdditionalSegment(size_t size, size_t offset, const char *name, const char *sclass, uchar stype)
{
  segment_t s;
  s.startEA = freechunk(0, size, -0xF);
  s.endEA   = s.startEA + size;
  s.sel     = allocate_selector((s.startEA-offset) >> 4);
  s.type    = stype;
  add_segm_ex(&s, name, sclass, ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.startEA - offset;
}

//----------------------------------------------------------------------
// special handling for areas
//lint -esym(528,handle_area) not referenced
static bool handle_area(ea_t start, ea_t end, const char *name, const char *aclass)
{
  if ( start >= end )
  {
    warning("Error in definition of segment %s %s\n", aclass, name);
    return false;
  }
  if ( strcmp(aclass, "CODE") == 0 )
  {
    AdditionalSegment(end-start, start, name, aclass, SEG_CODE);
  }
  else if ( strcmp(aclass, "DATA") == 0 )
  {
    uchar type = stristr(name, "FSR") != NULL ? SEG_IMEM : SEG_DATA;
    AdditionalSegment(end-start, start, name, aclass, type);
  }
  else
  {
    return false;
  }
  return true;
}

//----------------------------------------------------------------------
static bool select_device(int resp_info)
{
  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(cfgfile, device, sizeof(device), NULL) )
  {
    qstrncpy(device, NONEPROC, sizeof(device));
    return false;
  }

  if ( !display_infotype_dialog(IORESP_ALL, &resp_info, cfgfile) )
    return false;

  set_device_name(device, resp_info & ~IORESP_PORT);
  setup_data_segment_pointers();

  if ( (resp_info & IORESP_PORT) != 0 )
  {
    if ( intmem == BADADDR )
    {
      AdditionalSegment(0x1000, 0, "INTMEM", NULL, SEG_IMEM);
      setup_data_segment_pointers();
    }
    for ( int i=0; i < numports; i++ )
    {
      ioport_t *p = ports + i;
      ea_t ea = p->address + intmem;
      ea_t oldea = get_name_ea(BADADDR, p->name);
      if ( oldea != ea )
      {
        if ( oldea != BADADDR )
          set_name(oldea, NULL);
        do_unknown(ea, DOUNK_EXPAND);
        set_name(ea, p->name);
      }
      if ( p->cmt != NULL )
        set_cmt(ea, p->cmt, true);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
static const char *idaapi set_idp_options(const char *keyword, int, const void *)
{
  if ( keyword != NULL )
    return IDPOPT_BADKEY;
  select_device(IORESP_PORT|IORESP_INT);
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
static int idaapi notify(processor_t::idp_notify msgid, ...) // Various messages:
{
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code )
    return code;


  switch ( msgid )
  {
    case processor_t::init:
      helper.create("$ Zilog Z8");
      inf.mf = 1;                                 // MSB first
      break;

    default:
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::newfile:
      {
        segment_t *sptr = get_first_seg();
        if ( sptr != NULL )
        {
          if ( sptr->startEA - get_segm_base(sptr) == 0 )
          {
            inf.beginEA = sptr->startEA + 0xC;
            inf.startIP = 0xC;
            if ( !inf.like_binary() )
            {
              // set default entries
              for( int i = 0; i < qnumber(entries); i++ )
              {
                ea_t ea = sptr->startEA + entries[i].off;
                if( isEnabled(ea) )
                {
                  doWord(ea, 2);
                  set_offset(ea, 0, sptr->startEA);
                  ea_t ea1 = sptr->startEA + get_word(ea);
                  auto_make_proc(ea1);
                  set_name(ea, entries[i].name);
                  set_cmt(sptr->startEA+get_word(ea), entries[i].cmt, 1);
                }
              }
            }
          }
          set_segm_class( sptr, "CODE" );
        }

        select_device(IORESP_ALL);

        if ( intmem == BADADDR )
        {
          AdditionalSegment(0x1000, 0, "INTMEM", NULL, SEG_IMEM);
          setup_data_segment_pointers();
        }
      }
      break;

    case processor_t::oldfile:
      {
        char buf[MAXSTR];
        if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
          set_device_name(buf, IORESP_NONE);
      }
      setup_data_segment_pointers();
      break;

    case processor_t::newseg:
      {                 // default DS is equal to CS
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[rVds-ph.regFirstSreg] = sptr->sel;
      }
  }
  va_end(va);

  return(1);
}

//--------------------------------------------------------------------------
static const asm_t Z8asm =
{
  AS_COLON,
  0,
  "Zilog Z8 assembler",
  0,
  NULL,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",       // Equ
  NULL,         // seg prefix
//  preline, NULL, operdim,
  NULL, NULL, NULL,
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

static const asm_t *const asms[] = { &Z8asm, NULL };

//--------------------------------------------------------------------------

#define FAMILY "Zilog Z8 series:"
static const char *const shnames[] = { "Z8", NULL };
static const char *const lnames[]  = { FAMILY"Zilog Z8 MCU", NULL };

//--------------------------------------------------------------------------

static const uchar retcode[]  = { 0xAF };   // ret
static const uchar iretcode[] = { 0xBF };   // iret

static const bytes_t retcodes[] =
{
  { sizeof(retcode),  retcode },
  { sizeof(iretcode), iretcode },
  { 0, NULL }
};

//-----------------------------------------------------------------------
// use simple translation
static ea_t idaapi z8_translate(ea_t base, adiff_t offset)
{
  return base+offset;
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_Z8,                      // id
  PRN_HEX
  |PR_RNAMESOK          // can use register names for byte names
  |PR_SEGTRANS          // segment translation is supported (codeSeg)
  |PR_BINMEM            // The module creates RAM/ROM segments for binary files
                        // (the kernel shouldn't ask the user about their sizes and addresses)
  |PR_SEGS              // has segment registers?
  |PR_SGROTHER,         // the segment registers don't contain
                        // the segment selectors, something else
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,    // short processor names (null term)
  lnames,     // long processor names (null term)

  asms,       // array of enabled assemblers

  notify,     // Various messages:

  header,     // produce start of text file
  footer,     // produce end of text file

  segstart,   // produce start of segment
  segend,     // produce end of segment

  z8_assumes,

  ana,
  emu,

  out,
  outop,
  z8_data,    //intel_data,
  NULL,       // compare operands
  NULL,       // can have type

  qnumber(RegNames),    // Number of registers
  RegNames,             // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,rRp,
  1,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0, Z8_last,
  Instructions,
  NULL,                 // int  (*is_far_jump)(int icode);
  z8_translate,         // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x); -- always, so leave it NULL
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  Z8_ret,               // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  NULL,                 // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
