/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ctype.h>
#include "pic.hpp"
#include <diskio.hpp>
#include <segregs.hpp>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "w", "f",
  "ACCESS",        // register for PIC18Cxx
  "BANKED",        // register for PIC18Cxx
  "FAST",          // register for PIC18Cxx
  "FSR0",          // register for PIC18Cxx
  "FSR1",          // register for PIC18Cxx
  "FSR2",          // register for PIC18Cxx
  "bank",
  "cs","ds",       // virtual registers for code and data segments
  "pclath",
  "pclatu"         // register for PIC18Cxx
};

//--------------------------------------------------------------------------
// 11 01xx kkkk kkkk RETLW   k           Return with literal in W
static const uchar retcode_0[] = { 0x08, 0x00 };  // return
static const uchar retcode_1[] = { 0x09, 0x00 };  // retfie
static const uchar retcode_2[] = { 0x00, 0x34 };  // retlw 0
static const uchar retcode_3[] = { 0x01, 0x34 };  // retlw 1

static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Microchip's MPALC
//-----------------------------------------------------------------------
static const asm_t mpalc =
{
  ASH_HEXF2|ASD_DECF3|ASB_BINF5|ASO_OCTF5|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "Microchip's MPALC",
  0,
  NULL,         // header lines
  "org",        // org
  "end",        // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  "data",       // ascii string directive
  "byte",       // byte directive
  "data",       // word directive
  NULL,         // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "res %s",     // uninited arrays
  "equ",        // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // "public" name keyword
  NULL,         // "weak"   name keyword
  NULL,         // "extrn"  name keyword
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  NULL,         // "align" keyword
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

static const asm_t *const asms[] = { &mpalc, NULL };

//--------------------------------------------------------------------------
struct portmap_t
{
  ea_t from;
  ea_t to;
};

static qvector<portmap_t> map;

static void free_mappings(void)
{
  map.clear();
}

static void add_mapping(ea_t from, ea_t to)
{
  if ( from != to )
  {
    deb(IDA_DEBUG_IDP, "add_mapping %a -> %a\n", from, to);
    portmap_t &p = map.push_back();
    p.from = from;
    p.to = to;
  }
}

ea_t map_port(ea_t from)
{
  for ( int i=0; i < map.size(); i++ )
    if ( map[i].from == from )
      return map[i].to;
  return from;
}

//--------------------------------------------------------------------------
static ioports_t ports;
qstring device;
static const char *cfgname = "pic12.cfg";

inline void get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, cfgname, bufsize);
}

// create the mapping table
static void create_mappings(void)
{
  free_mappings();
  for ( int i=0; i < ports.size(); i++ )
  {
    const char *name = ports[i].name.c_str();
    ea_t nameea = get_name_ea(BADADDR, name);
    if ( nameea != BADADDR && nameea > dataseg )
      add_mapping(ports[i].address, nameea-dataseg);
  }
}

//----------------------------------------------------------------------
static ea_t AddSegment(ea_t start, size_t size, ea_t base, const char *name, uchar type)
{
  segment_t s;
  s.start_ea = start;
  s.end_ea   = start + size;
  s.sel     = allocate_selector(base >> 4);
  s.type    = type;
  s.align   = saRelByte;
  s.comb    = scPub;
  add_segm_ex(&s, name, NULL, ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.start_ea;
}

//----------------------------------------------------------------------
// special handling for 16-bit PICs
// for CODE segments use addresses as-is
// for DATA segments, start from dataseg base
//lint -esym(528,handle_area)
static bool handle_area(ea_t start, ea_t end, const char *name, const char *aclass)
{
  if ( ptype != PIC16 )
    return false;
  if ( strcmp(aclass, "CODE") == 0 )
  {
    AddSegment(start, end-start, 0, name, SEG_CODE);
  }
  else if ( strcmp(aclass, "DATA") == 0 )
  {
    if ( dataseg == BADADDR )
      dataseg = free_chunk(0, 0x1000, -0xF);
    uchar type = stristr(name, "FSR") != NULL ? SEG_IMEM : SEG_DATA;
    AddSegment(dataseg + start, end-start, dataseg, name, type);
  }
  else
  {
    return false;
  }
  return true;
}

#define NO_GET_CFG_PATH
#define AREA_PROCESSING handle_area

#include "../iocommon.cpp"
static void load_symbols_without_infotype(int /*respect_args*/)
{
  ports.clear();
  read_ioports(&ports, &device, cfgname, callback);
  create_mappings();
}

static void load_symbols(int respect_args)
{
  if ( display_infotype_dialog(IORESP_ALL, &respect_args, cfgname) )
    load_symbols_without_infotype(respect_args);
}

const char *find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ports, address);
  return port ? port->name.c_str() : NULL;
}

const ioport_bits_t *find_bits(ea_t address)
{
  const ioport_t *port = find_ioport(ports, address);
  return port ? (&port->bits) : NULL;
}

const char *find_bit(ea_t address, int bit)
{
  address = map_port(address);
  const ioport_bit_t *b = find_ioport_bit(ports, address, bit);
  return b ? b->name.c_str() : NULL;
}

//----------------------------------------------------------------------
static void apply_symbols(void)
{
  free_mappings();
  if ( dataseg != BADADDR )
  {
    for ( int i=0; i < ports.size(); i++ )
    {
      ea_t ea = calc_data_mem(ports[i].address);
      segment_t *s = getseg(ea);
      if ( s == NULL || s->type != SEG_IMEM )
        continue;
      create_byte(ea, 1);
      const char *name = ports[i].name.c_str();
      if ( !set_name(ea, name, SN_NOCHECK|SN_NOWARN) )
        set_cmt(ea, name, 0);
    }
    for ( segment_t *d = getseg(dataseg); d != NULL; d = get_next_seg(d->start_ea) )
    {
      if ( d->type != SEG_IMEM )
        continue;
      ea_t ea = d->start_ea;
      ea_t dataend = d->end_ea;
      while ( 1 )
      {
        ea = next_unknown(ea, dataend);
        if ( ea == BADADDR )
          break;
        ea_t end = next_that(ea, dataend, f_is_head);
        if ( end == BADADDR )
          end = dataend;
        create_byte(ea, end-ea);
      }
    }
    create_mappings();
  }
}

//------------------------------------------------------------------
static void setup_device(int lrespect_info)
{
  if ( choose_ioport_device(&device, cfgname, parse_area_line0) )
  {
    // we don't pass IORESP_PORT because that would rename bytes in the code segment
    // we'll handle port renaming ourselves
    if ( display_infotype_dialog(IORESP_ALL, &lrespect_info, cfgname) )
    {
      set_device_name(device.c_str(), lrespect_info & ~IORESP_PORT);
      if ( (lrespect_info & IORESP_PORT) != 0 )
         apply_symbols();
    }
  }
}

//----------------------------------------------------------------------
static ea_t AdditionalSegment(size_t size, ea_t offset, const char *name)
{
  ea_t start = free_chunk(0, size, -0xF);
  return AddSegment(start, size, start - offset, name, SEG_IMEM) - offset;
}

//--------------------------------------------------------------------------

netnode helper;
ea_t dataseg = BADADDR;
proctype_t ptype = PIC12;
ushort idpflags = IDP_MACRO;

static const proctype_t ptypes[] =
{
  PIC12,
  PIC14,
  PIC16
};

//--------------------------------------------------------------------------
static int idaapi choose_device(int, form_actions_t &)
{
  if ( choose_ioport_device(&device, cfgname) )
  {
    load_symbols(IORESP_ALL);
    apply_symbols();
  }
  return 0;
}

static const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  if ( keyword == NULL )
  {
    if ( ptype != PIC16 )
    {
      static const char form[] =
        "HELP\n"
        "PIC specific options\n"
        "\n"
        " Use macro instructions\n"
        "\n"
        "       If this option is on, IDA will try to combine several instructions\n"
        "       into a macro instruction\n"
        "       For example,\n"
        "\n"
        "               comf    x,1\n"
        "               incf    x,w\n"
        "\n"
        "       will be replaced by\n"
        "\n"
        "               negf    x,d\n"
        "\n"
        "ENDHELP\n"
        "PIC specific options\n"
        "\n"
        " <Use ~m~acro instructions:C>>\n"
        "\n"
        " <~C~hoose device name:B:0::>\n"
        "\n"
        "\n";
      ask_form(form, &idpflags, choose_device);
    }
    else
    {
      static const char form[] =
        "PIC specific options\n"
        "\n"
        " <~C~hoose device name:B:0::>\n"
        "\n"
        "\n";
      ask_form(form, choose_device);
    }
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "PIC_MACRO") == 0 )
    {
      setflag(idpflags, IDP_MACRO, *(int*)value != 0);
      return IDPOPT_OK;
    }
    return IDPOPT_BADKEY;
  }
}

//--------------------------------------------------------------------------
static ssize_t idaapi idb_callback(void *, int code, va_list /*va*/)
{
  switch ( code )
  {
    case idb_event::closebase:
    case idb_event::savebase:
      helper.altset(0,  ea2node(dataseg));
      helper.altset(-1, idpflags);
      helper.supset(0,  device.c_str());
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
      helper.create("$ pic");
      helper.supstr(&device, 0);
      break;

    case processor_t::ev_term:
      free_mappings();
      ports.clear();
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    case processor_t::ev_newfile:   // new file loaded
      {
        segment_t *s0 = get_first_seg();
        if ( s0 != NULL )
        {
          ea_t firstEA = s0->start_ea;
          if ( ptype == PIC12 || ptype == PIC14 )
          {
            set_segm_name(s0, "CODE");
            dataseg = AdditionalSegment(0x200, 0, "DATA");
            setup_device(IORESP_INT|IORESP_PORT);
          }
          else
          {
            setup_device(IORESP_ALL);
          }
          s0 = getseg(firstEA);
          if ( s0 != NULL )
          {
            set_default_sreg_value(s0, BANK, 0);
            set_default_sreg_value(s0, PCLATH, 0);
            set_default_sreg_value(s0, PCLATU, 0);
          }
          segment_t *s1 = getseg(dataseg);
          if ( s1 != NULL )
          {
            set_default_sreg_value(s1, BANK, 0);
            set_default_sreg_value(s1, PCLATH, 0);
            set_default_sreg_value(s1, PCLATU, 0);
          }
        }
      }
      break;

    case processor_t::ev_oldfile:   // old file loaded
      idpflags = (ushort)helper.altval(-1);
      dataseg  = node2ea(helper.altval(0));
      load_symbols_without_infotype(IORESP_PORT);
      for ( segment_t *s=get_first_seg(); s != NULL; s=get_next_seg(s->start_ea) )
      {
        if ( s->defsr[PCLATH-ph.reg_first_sreg] == BADSEL )
          s->defsr[PCLATH-ph.reg_first_sreg] = 0;
      }
      break;

    case processor_t::ev_newprc:    // new processor type
      {
        int n = va_arg(va, int);
        // bool keep_cfg = va_argi(va, bool);
        static bool set = false;
        if ( set )
          return 0;
        set = true;
        if ( ptypes[n] != ptype )
        {
          ptype = ptypes[n];
          ph.cnbits = 12 + 2*n;
        }
        switch ( ptype )
        {
          case PIC12:
            register_names[PCLATH] = "status";
            cfgname = "pic12.cfg";
            break;
          case PIC14:
            cfgname = "pic14.cfg";
            break;
          case PIC16:
            register_names[BANK] = "bsr";
            cfgname = "pic16.cfg";
            ph.cnbits = 8;
            ph.reg_last_sreg = PCLATU;
            break;
          default:
            error("interr in setprc");
            break;
        }
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        pic_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        pic_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        pic_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        pic_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        pic_assumes(*ctx);
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

    case processor_t::ev_out_data:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        bool analyze_only = va_argi(va, bool);
        pic_data(*ctx, analyze_only);
        return 1;
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
        *frsize = PIC_get_frame_retsize(pfn);
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
#define FAMILY "Microchip PIC:"
static const char *const shnames[] =
{ "PIC12Cxx",
  "PIC16Cxx",
  "PIC18Cxx",
  NULL
};
static const char *const lnames[] =
{ FAMILY"Microchip PIC PIC12Cxx - 12 bit instructions",
  "Microchip PIC PIC16Cxx - 14 bit instructions",
  "Microchip PIC PIC18Cxx - 16 bit instructions",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_PIC,               // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER
  | PR_STACK_UP
  | PR_RNAMESOK,
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  12,                     // 12/14/16 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  BANK,                 // first
  PCLATH,               // last
  0,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  PIC_null,
  PIC_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  PIC_return,           // Icode of return instruction. It is ok to give any of possible return instructions
};
