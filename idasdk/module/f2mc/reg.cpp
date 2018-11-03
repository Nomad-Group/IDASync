/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ctype.h>
#include "f2mc.hpp"
#include <diskio.hpp>
#include <segregs.hpp>

netnode helper;
proctype_t ptype = F2MC16LX;
ushort idpflags = F2MC_MACRO;

static const proctype_t ptypes[] =
{
  F2MC16L,
  F2MC16LX
};

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "A",   // accumulator
  "AL",  // accumulator
  "AH",  // accumulator
  "PC",  // program counter
  "SP",  // stack pointer
  "R0",
  "R1",
  "R2",
  "R3",
  "R4",
  "R5",
  "R6",
  "R7",
  "RW0",
  "RW1",
  "RW2",
  "RW3",
  "RW4",
  "RW5",
  "RW6",
  "RW7",
  "RL0",
  "RL1",
  "RL2",
  "RL3",

  "PCB",     // program bank register
  "DTB",     // data bank register
  "ADB",     // additional data bank register
  "SSB",     // system stack bank register
  "USB",     // user stack bank register
  "CCR",     // condition code register
  "DPR",     // direct page register
  "cs","ds", // virtual registers for code and data segments

  "SPB", // stack pointer bank register
  "PS",  // processor status
  "ILM", // interrupt level mask register
  "RP"   // register bank pointer
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x66 };  // retp
static const uchar retcode_1[] = { 0x67 };  // ret
static const uchar retcode_2[] = { 0x6B };  // reti

static const bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Fujitsu FASM
//-----------------------------------------------------------------------
static const asm_t fasm =
{
  AS_N2CHR|AS_NCMAS|ASH_HEXF3|ASD_DECF0|ASO_OCTF1|ASB_BINF3|AS_ONEDUP,
  0,
  "Fujitsu FASM",
  0,
  NULL,         // header lines
  ".org",       // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".data.b",    // byte directive
  ".data.w",    // word directive
  ".data.l",    // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".res.b %s",  // uninited arrays
  ".equ",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // "public" name keyword
  NULL,         // "weak"   name keyword
  NULL,         // "extrn"  name keyword
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
};

static const asm_t *const asms[] = { &fasm, NULL };

//--------------------------------------------------------------------------
static ioports_t ports;
qstring device;
static const char *cfgname = NULL;

#define CUSTOM1 "FSR"


//lint -esym(528,handle_area)
#define AREA_PROCESSING handle_area
#define callback handle_interrupt
static const char *idaapi handle_interrupt(const ioports_t &iop, const char *line);

static bool handle_area(ea_t start, ea_t end, const char *name, const char *aclass)
{
  const bool split = end > start && (end - start) > 0x10000;
  for ( ea_t chunk_ea = start; chunk_ea < end; chunk_ea += 0x10000 )
  {
    ea_t segbase = (chunk_ea >> 16) << 12;
    sel_t sel = allocate_selector(segbase);
    qstring nm(name);
    if ( split )
      nm.cat_sprnt("_%02X", uint32((chunk_ea >> 16) & 0xFF));
    ea_t chunk_end = chunk_ea + 0x10000;
    if ( chunk_end > end )
      chunk_end = end;
    add_segm(sel, chunk_ea, chunk_end, nm.c_str(), aclass);
  }
  return true;
}

#include "../iocommon.cpp"

//-------------------------------------------------------------------------
static const char *idaapi handle_interrupt(const ioports_t &iop, const char *line)
{
  const char *ret = NULL;
  bool handled = false;
  char word[MAXSTR];
  ea_t ea1;
  int len;
  if ( qsscanf(line, "interrupt %s %" FMT_EA "i%n", word, &ea1, &len) == 2 ) //lint !e706 nominally inconsistent format
  {
    if ( (respect_info & IORESP_INT) != 0 )
    {
      segment_t *s = getseg(ea1);
      ea_t proc;
      if ( s != NULL )
      {
        create_dword(ea1, 4);
        proc = get_dword(ea1);
        if ( proc != 0xFFFFFFFF )
        {
          op_plain_offset(ea1, 0, 0);
          add_entry(proc, proc, word, true);

          const char *ptr = &line[len];
          ptr = skip_spaces(ptr);
          if ( ptr[0] != '\0' )
            set_cmt(ea1, ptr, true);

          handled = true;
        }
      }
    }
  }
  if ( !handled )
    ret = standard_callback(iop, line);
  return ret;
}

static void load_symbols(int _respect_info)
{
  if ( cfgname != NULL )
  {
    deviceparams.qclear();
    respect_info = _respect_info;
    if ( !inf.like_binary() )
      respect_info &= ~2;
    ports.clear();
    read_ioports(&ports, &device, cfgname, callback);
    if ( respect_info )
    {
      for ( int i=0; i < ports.size(); i++ )
      {
        ea_t ea = ports[i].address;
        create_byte(ea, 1);
        const char *name = ports[i].name.c_str();
        if ( !set_name(ea, name, SN_NOCHECK|SN_NOWARN) )
          set_cmt(ea, name, 0);
        else
          set_cmt(ea, ports[i].cmt.c_str(), true);
      }
    }
  }
}

const char *find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ports, address);
  return port ? port->name.c_str() : NULL;
}

const char *find_bit(ea_t address, int bit)
{
  const ioport_bit_t *b = find_ioport_bit(ports, address, bit);
  return b ? b->name.c_str() : NULL;
}

//--------------------------------------------------------------------------
static void f2mc_set_device_name(const char *dev, int _respect_info)
{
  if ( dev != NULL )
  {
    device = dev;
    helper.supset(0, dev);
  }
  load_symbols(_respect_info);
}

//-------------------------------------------------------------------------
static void choose_and_set_device(int flags)
{
  if ( choose_ioport_device(&device, cfgname, parse_area_line0) )
    f2mc_set_device_name(device.c_str(), flags);
}

//--------------------------------------------------------------------------
inline void choose_device()
{
  choose_and_set_device(IORESP_PORT|IORESP_INT);
}

//--------------------------------------------------------------------------
static int idaapi choose_device_cb(int, form_actions_t &)
{
  choose_device();
  return 0;
}

//--------------------------------------------------------------------------
static const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  if ( keyword == NULL )
  {
    static const char form[] =
      "HELP\n"
      "F2MC specific options\n"
      "\n"
      " Use macro instructions\n"
      "\n"
      "       If this option is on, IDA will try to combine several instructions\n"
      "       into a macro instruction\n"
      "       For example,\n"
      "\n"
      "            sbbs    data:7, $1\n"
      "            bra     $2\n"
      "          $1:\n"
      "            jmp     LABEL\n"
      "          $2:\n"
      "\n"
      "       will be replaced by\n"
      "\n"
      "            sbbs16  data:7, LABEL\n"
      "\n"
      "ENDHELP\n"
      "F2MC specific options\n"
      "\n"
      " <Use ~m~acro instructions:C>>\n"
      "\n"
      " <~C~hoose device name:B:0::>\n"
      "\n"
      "\n";
    ask_form(form, &idpflags, choose_device_cb);
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( streq(keyword, "F2MC_MACRO") )
    {
      setflag(idpflags, F2MC_MACRO, *(int*)value != 0);
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
      helper.altset(-1, idpflags);
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_init:
//      __emit__(0xCC);   // debugger trap
      hook_to_notification_point(HT_IDB, idb_callback);
      helper.create("$ f2mc");
      if ( helper.supstr(&device, 0) > 0 )
        f2mc_set_device_name(device.c_str(), IORESP_NONE);
      inf.set_wide_high_byte_first(true);
      break;

    case processor_t::ev_term:
      ports.clear();
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    case processor_t::ev_newfile:   // new file loaded
      set_segm_name(get_first_seg(), "CODE");
      choose_and_set_device(IORESP_ALL);
      for ( int i = DTB; i <= rVds; i++ )
      {
        for ( segment_t *s=get_first_seg(); s != NULL; s=get_next_seg(s->start_ea) )
          set_default_sreg_value(s, i, 0);
      }
      break;

    case processor_t::ev_oldfile:   // old file loaded
      idpflags = (ushort)helper.altval(-1);
      break;

    case processor_t::ev_newprc:    // new processor type
      {
        ptype = ptypes[va_arg(va, int)];
        // bool keep_cfg = va_argi(va, bool);
        switch ( ptype )
        {
          case F2MC16L:
            cfgname = "f2mc16l.cfg";
            break;
          case F2MC16LX:
            cfgname = "f2mc16lx.cfg";
            break;
          default:
            error("interr: setprc");
            break;
        }
        device.qclear();
        if ( get_first_seg() != NULL )
          choose_device();
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        f2mc_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        f2mc_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        f2mc_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        f2mc_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        f2mc_assumes(*ctx);
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
  return 0;
}

//-----------------------------------------------------------------------
#define FAMILY "Fujitsu F2MC:"

static const char *const shnames[] =
{ "F2MC16L",
  "F2MC16LX",
  NULL
};
static const char *const lnames[] =
{ FAMILY"Fujitsu F2MC 16L",
  "Fujitsu F2MC 16LX",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_F2MC,              // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER,
                          // flag2
  PR2_IDP_OPTS,           // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  DTB,                  // first. We don't start at PCB, because
                        // PCB == cs, and the way to get addresses
                        // right is not to modify PCB, but rather
                        // create the segmentation correctly.
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  F2MC_null,
  F2MC_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  F2MC_ret,             // Icode of return instruction. It is ok to give any of possible return instructions
};
