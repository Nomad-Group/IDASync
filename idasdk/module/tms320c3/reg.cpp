/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <math.h>
#include "tms320c3x.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <ieee.h>

static const char *const register_names[] =
{
  // Extended-precision registers
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  // Auxiliary registers
  "ar0",
  "ar1",
  "ar2",
  "ar3",
  "ar4",
  "ar5",
  "ar6",
  "ar7",

  // Index register n
  "ir0",
  "ir1",

  "bk",   // Block-size register
  "sp",   // System-stack pointer
  "st",   // Status register
  "ie",   // CPU/DMA interrupt-enable register
  "if",   // CPU interrupt flag
  "iof",  // I/O flag
  "rs",   // Repeat start-address
  "re",   // Repeat end-address
  "rc",   // Repeat counter

  // segment registers
  "dp",      // Data-page pointer
  "cs","ds", // virtual registers for code and data segments

};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x78, 0x80, 0x00, 0x00 }; // 0x78800000    //retsu
static const uchar retcode_1[] = { 0x78, 0x00, 0x00, 0x00 }; // 0x78000000    //retiu

static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      TMS320C3X ASM
//-----------------------------------------------------------------------
static const asm_t fasm =
{
  AS_N2CHR|ASH_HEXF0|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP|AS_COLON,
  0,
  "ASM500",
  0,
  NULL,         // header lines
  NULL,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  ".word",      // byte directive
  ".long",      // word directive
  NULL,         // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space 32*%s",// uninited arrays
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
  AS2_BYTE1CHAR,// one character per byte
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gnuasm =
{
  AS_N2CHR|ASH_HEXF3|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP|AS_COLON|AS_ASCIIC,
  0,
  "GNU assembler",
  0,
  NULL,         // header lines
  NULL,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  ".word",      // byte directive
  ".long",      // word directive
  NULL,         // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".zero 2*%s", // uninited arrays
  ".asg",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  ".weak",      // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
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
  AS2_BYTE1CHAR,// one character per byte
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static const asm_t *const asms[] = { &fasm, &gnuasm, NULL };

//--------------------------------------------------------------------------
static ioports_t ports;
qstring device;

//lint -e528
static bool entry_processing(ea_t ea, const char *name, const char *cmt)
{
  set_name(ea, name);
  set_cmt(ea, cmt, 0);
  return true;
}

#define ENTRY_PROCESSING entry_processing
#include "../iocommon.cpp"

//----------------------------------------------------------------------
static bool select_device(int lrespect_info)
{
  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(&device, cfgfile) )
  {
    device = NONEPROC;
    return false;
  }

  if ( !display_infotype_dialog(IORESP_ALL, &lrespect_info, cfgfile) )
    return false;

  set_device_name(device.c_str(), lrespect_info);
  return true;
}

//----------------------------------------------------------------------
static float conv32(int32 A)   // Преобразование 32 bit TMS float -> double
{
  int32 mask, f, i, s;
  float mant;
  int8 e;

  // Порядок (exponent) signed 8 bit
  e = A >> 24;

  //Знак  (sign) boolean 1 bit
  s = (A & 0x00800000) >> 23;

  //дробная часть (fractional) unsigned 23 bit
  f =  A & 0x007FFFFF;

  if ( s )
  {
    f ^= 0x007FFFFF;
    f++;
  }

  mant = 1;       //Мантисса (1<M<2)
  mask = 0x00800000;        // Маска текущего бита (начинаем со знакового разряда потому, что может возниктунь дополнение при Neg мантиссе)

  for ( i = 0; i <= 23; i++ )
  {       //Получение мантиссы
    if ( f & mask )
      mant += (float)pow(double(2), -i);
    mask >>= 1;
  }

  if ( e == -128 && f == 0 && s == 0 )
    mant = 0;

  return float(pow(double(-1), s) * mant * pow(double(2), e));
}

//----------------------------------------------------------------------
static float conv16(int16 A)   // Преобразование 16 bit TMS float -> double
{
  int16 mask, f, i, s;
  float mant;
  int8 e;


  // Порядок (exponent) signed 4 bit
  e = A >> 12;
  if ( e > 7 )
    e = -((e ^ 0x0f) + 1);

  // Знак  (sign) boolean 1 bit
  s = (A & 0x0800) >> 11;

  // дробная часть (fractional) unsigned 11 bit
  f =  A & 0x07FF;

  if ( s )
  {
    f ^= 0x07FF;
    f++;
  }

  mant = 1;       //Мантисса (1<M<2)
  mask =       0x0800;    // Маска текущего бита (начинаем со знакового разряда потому, что может возниктунь дополнение при Neg мантиссе)

  for ( i = 0; i <= 11; i++ )
  { // Получение мантиссы
    if ( f & mask )
      mant += (float)pow(double(2), -i);
    mask >>= 1;
  }

  if ( e == -8 && f == 0 && s == 0 )
    mant = 0;

  return float(pow(double(-1), s) * mant * pow(double(2), e));
}

//--------------------------------------------------------------------------
//lint -esym(818,m)
int idaapi tms_realcvt(void *m, ushort *e, ushort swt)
{
  int ret;
  int32 A;
  int16 B;

  union
  {
    float pfl;
    int32 pint;
  };

  switch ( swt )
  {

   case 0:                // TmsFloat 16bit to e
      {
        memcpy(&B, m, 2);
        pfl = conv16(B);
        pint = swap32(pint);
        ret = ieee_realcvt(&pint, e, 1);
        break;
      }
   case 1:                // TmsFloat 32bit to e
      {
        memcpy(&A, m, 4);
        pfl = conv32(A);
        pint = swap32(pint);
        ret = ieee_realcvt(&pint, e, 1);
        break;
      }
    default:
        msg("real_cvt_error swt = %d \n", swt);
      return -1;
  }
  return ret;
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
netnode helper;
ushort idpflags;        // not used?

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
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_to_notification_point(HT_IDB, idb_callback);
      helper.create("$ tms320c3x");
      inf.set_be(true); // MSB first
      inf.set_wide_high_byte_first(true);
      init_analyzer();
      break;

    case processor_t::ev_term:
      ports.clear();
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    case processor_t::ev_newfile:   // new file loaded
      inf.set_wide_high_byte_first(false);
      if ( inf.like_binary() )
      {
        segment_t *s0 = get_first_seg();
        if ( s0 != NULL )
        {
          set_segm_name(s0, "CODE");
          segment_t *s1 = get_next_seg(s0->start_ea);
          for ( int i = dp; i <= rVds; i++ )
          {
            set_default_sreg_value(s0, i, BADSEL);
            set_default_sreg_value(s1, i, BADSEL);
          }
        }
        select_device(IORESP_ALL);
      }
      break;

    case processor_t::ev_oldfile:   // old file loaded
      inf.set_wide_high_byte_first(false);
      idpflags = (ushort)helper.altval(-1);
      if ( helper.supstr(&device, -1) > 0 )
        set_device_name(device.c_str(), IORESP_NONE);
      break;

    case processor_t::ev_is_basic_block_end:
      {
        const insn_t &insn = *va_arg(va, const insn_t *);
        return is_basic_block_end(insn) ? 1 : 0;
      }

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
        int code1 = tms_realcvt(m, e, swt);
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
#define FAMILY "TMS320C3x Series:"
static const char *const shnames[] =
{
  "TMS320C3",
  NULL
};
static const char *const lnames[] =
{
  FAMILY"Texas Instruments TMS320C3X",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_TMS320C3,          // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER
  | PR_ALIGN
  | PR_USE32
  | PR_DEFSEG32
  | PR_DELAYED,
                          // flag2
    PR2_REALCVT           // the module has 'realcvt' event implementation
  | PR2_IDP_OPTS,         // the module has processor-specific configuration options
  32,                     // 32 bits in a byte for code segments
  32,                     // 32 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  dp,                   // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  TMS320C3X_null,
  TMS320C3X_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 4,7,15,19 },        // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  TMS320C3X_RETSU,      // Icode of return instruction. It is ok to give any of possible return instructions
};
