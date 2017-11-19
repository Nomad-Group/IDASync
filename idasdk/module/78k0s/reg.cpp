/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "78k_0s.hpp"
#include <srarea.hpp>
#include <diskio.hpp>

//----------------------------------------------------------------------
static const char *const RegNames[] =
{
  "X", "A", "C", "B", "E", "D", "L", "H", "AX", "BC", "DE","HL",
  "PSW", "SP", "s", "cc", "dpr",
  "CY",
  "cs", "ds"
};
//----------------------------------------------------------------------
static const asm_t nec78k0s =
{
  AS_COLON | ASH_HEXF0 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF4 | AS_N2CHR | AS_ONEDUP | AS_NOXRF,
  UAS_NOSPA,
  "NEC _78K_0S Assembler",
  0,
  NULL,     //header
  NULL,
  ".org",
  ".end",

  ";",        // comment string
  '"',        // string delimiter
  '\'',       // char delimiter
  "'\"",      // special symbols in char and string constants

  ".db",    // ascii string directive
  ".db",    // byte directive
  ".dw",    // word directive
  NULL,     // no double words
  NULL,     // no qwords
  NULL,     // oword  (16 bytes)
  NULL,     // no float
  NULL,     // no double
  NULL,     // no tbytes
  NULL,     // no packreal
  NULL,     //".db.#s(b,w) #d,#v",   // #h - header(.byte,.word)
                    // #d - size of array
                    // #v - value of array elements
                    // #s - size specifier
  ".rs %s",    // uninited data (reserve space)
  ".equ",
  NULL,         // seg prefix
  NULL,         // preline for checkarg
  NULL,      // checkarg_atomprefix
  NULL,   // checkarg operations
  NULL,   // XlatAsciiOutput
  "*",    // a_curip
  NULL,         // returns function header line
  NULL,         // returns function footer line
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
//----------------------------------------------------------------------
#define FAMILY "NEC series:"
static const char *const shnames[] =
{
  "78k0s",
  NULL
};
static const char *const lnames[] =
{
  FAMILY"NEC 78K/0S",
  NULL
};
static const asm_t *const asms[] =
{
  &nec78k0s,
  NULL
};
//--------------------------------------------------------------------------
//���� �����⮢
static const uchar retcNEC78K0S_0[] = { 0x24 };    //reti
static const uchar retcNEC78K0S_1[] = { 0x20 };    //ret

static const bytes_t retcodes[] =
{
  { sizeof(retcNEC78K0S_0), retcNEC78K0S_0 },
  { sizeof(retcNEC78K0S_1), retcNEC78K0S_1 },
  { 0, NULL }
};

//----------------------------------------------------------------------
static netnode helper;
char device[MAXSTR] = "";
static size_t numports = 0;
static ioport_t *ports = NULL;

#include "../iocommon.cpp"

//------------------------------------------------------------------
bool nec_find_ioport_bit(int port, int bit)
{
//���� ��� �� ॣ���� � ᯨ᪥ ���⮢
  const ioport_bit_t *b = find_ioport_bit(ports, numports, port, bit);
  if ( b != NULL && b->name != NULL )
  {
    //�뢮��� ��� ��� �� ॣ����
    out_line(b->name, COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static int idaapi notify(processor_t::idp_notify msgid, ...)
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
      inf.mf = 0;
      helper.create("$ 78k0s");
    default:
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::newfile:
      {
      //�㭪�� "�롨ࠥ�" �� 㪠������� 䠩�� *.cfg �� �����(������)
      //� �⮡ࠦ��� �� � ���������� ����, � ���஬ ���짮��⥫� ����� �����
      //�㦭� ��� ������. ��᫥ �롮� ��� ������ �������� � ��६����� device
      //��㬮�砭�� � DLG �뤥��� ������ ����� 㪠��� � ��६����� .default
      //����� �ᯮ�������� � ��砫� 䠩�� *.cfg
      inf.s_genflags |= INFFL_LZERO;
      char cfgfile[QMAXFILE];
      get_cfg_filename(cfgfile, sizeof(cfgfile));
      if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
        //��⠭�������� � �� ��� ��� ��࠭���� ������
        //����뢠�� �� "�����"(�����)  �⭮��騥�� � �⮬� �������
        //� ������뢠�� � 䠩�� �� ����� ���⠭�� �� *.cfg 䠩��
        set_device_name(device, IORESP_ALL);
      } break;

    case processor_t::newprc:
      {
      char buf[MAXSTR];
      if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
        set_device_name(buf, IORESP_PORT);
      } break;

    case processor_t::newseg:    // new segment
      {
      segment_t *s = va_arg(va, segment_t *);
      // Set default value of DS register for all segments
      set_default_dataseg(s->sel);
      } break;

  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,
  PLFM_NEC_78K0S,            // id
  PRN_HEX|PR_SEGTRANS,
  8,                    // 8 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  std_gen_segm_footer,

  NULL,

  ana,
  emu,

  out,
  outop,
  intel_data,
  NULL,         //  cmp_opnd,  // 0 if not cmp 1 if eq
  NULL,         //  can_have_type,  //&op    // 1 -yes 0-no    //reg

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Regsiter names
  NULL,                         // get abstract register

  0,                            // Number of register files
  NULL,                         // Register file names
  NULL,                         // Register descriptions
  NULL,                         // Pointer to CPU registers

  Rcs,Rds,
  0,                            // size of a segment register
  Rcs,Rds,

  NULL,                         // No known code start sequences
  retcodes,

  0,
  NEC_78K_0S_last,
  Instructions,
};
