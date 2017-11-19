/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"
#include <diskio.hpp>
#include <srarea.hpp>

//----------------------------------------------------------------------
static const char *const RegNames[] =
{
  "X", "A", "C", "B", "E", "D", "L", "H", "AX", "BC", "DE","HL",
  "PSW", "SP", "CY", "RB0", "RB1", "RB2", "RB3",
  "cs", "ds"
};

//----------------------------------------------------------------------
static const asm_t nec78k0 =
{
  AS_COLON | ASB_BINF4 | AS_N2CHR ,
  // ���짮��⥫�᪨� 䫠���
  0,
  "NEC 78K0 Assembler",                 // �������� ��ᥬ����
  0,                                                    // ����� � help'e
  NULL,                                                 // ��⮧��������
  NULL,                                                 // ���ᨢ �� �ᯮ������� ������権
  ".org",
  ".end",

  ";",        // comment string
  '"',        // string delimiter
  '\'',       // char delimiter
  "'\"",      // special symbols in char and string constants

  ".db",    // ascii string directive
  ".db",    // byte directive
  ".dw",    // word directive
  ".dd",     // no double words
  NULL,     // no qwords
  NULL,     // oword  (16 bytes)
  NULL,     // no float
  NULL,     // no double
  NULL,     // no tbytes
  NULL,     // no packreal
  "#d dup(#v)",     //".db.#s(b,w) #d,#v",   // #h - header(.byte,.word)
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
  "$",    // a_curip

  NULL,         // returns function header line
  NULL,         // returns function footer line
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL         // align

  ,'(', ')',     // lbrace, rbrace
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
  "78k0",
  NULL
};
static const char *const lnames[] =
{
  FAMILY"NEC 78K0",
  NULL
};

static const asm_t *const asms[] =
{
  &nec78k0,
  NULL
};

//--------------------------------------------------------------------------
static const uchar retcNEC78K0_0[] = { 0xAF };    //ret
static const uchar retcNEC78K0_1[] = { 0x9F };    //retb
static const uchar retcNEC78K0_2[] = { 0x8F };    //reti
static const uchar retcNEC78K0_3[] = { 0xBF };    //brk
static const bytes_t retcodes[] =
{
  { sizeof(retcNEC78K0_0), retcNEC78K0_0 },
  { sizeof(retcNEC78K0_1), retcNEC78K0_1 },
  { sizeof(retcNEC78K0_2), retcNEC78K0_2 },
  { sizeof(retcNEC78K0_3), retcNEC78K0_3 },
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
  if ( b != NULL && b->name != NULL ){
    //�뢮��� ��� ��� �� ॣ����
    out_line(b->name, COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------

void set_dopolnit_info(void)
{
  for ( int banknum = 0; banknum < 4; banknum++)
  {
    for ( int Regs = 0; Regs < 8; Regs++)
    {
      char temp[100];
      qsnprintf(temp, sizeof(temp), "Bank%d_%s", banknum, RegNames[Regs]);
      //����塞 �����
      ushort Addr = ushort(0xFEE0+((banknum*8)+Regs));
      //��⠭�������� ��� ����
      set_name(Addr, temp);
      //��⠭�������� ������਩
      qsnprintf(temp, sizeof(temp), "Internal high-speed RAM (Bank %d registr %s)", banknum, RegNames[Regs]);
      set_cmt(Addr, temp, true);
    }
  }
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
  if ( code ) return code;

  switch ( msgid )
  {
    case processor_t::init:
      inf.mf = 0;
      inf.s_genflags |= INFFL_LZERO;
      helper.create("$ 78k0");
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::newfile:
      //�뢮��� ���. ���� �����஢, � �������� ����� �㦭�, ���뢠�� ��� ��࠭���
      //������ ���ଠ�� �� cfg. �� ��⠭�� ���ଠ樨 ������뢠�� ����� � ॣ����
      {
        char cfgfile[QMAXFILE];
        get_cfg_filename(cfgfile, sizeof(cfgfile));
        if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
          set_device_name(device, IORESP_ALL);
        set_dopolnit_info();
      }
      break;

    case processor_t::newprc:
      {
        char buf[MAXSTR];
        if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
          set_device_name(buf, IORESP_PORT);
      }
      break;

    case processor_t::newseg:
      {
        segment_t *s = va_arg(va, segment_t *);
        // Set default value of DS register for all segments
        set_default_dataseg(s->sel);
      }
      break;
    default:
      break;
  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_NEC_78K0,                // id ������
  PRN_HEX|PR_SEGTRANS|PR_SEGS,  // can use register names for byte names
  8,                                                    // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte

  shnames,                      // ���⪨� ����� �����஢ (�� 9 ᨬ�����)
  lnames,                       // ������ ����� �����஢

  asms,                         // ᯨ᮪ ��������஢

  notify,                       // �㭪�� �����饭��

  N78K_header,                  // ᮧ����� ��������� ⥪��
  N78K_footer,                  // ᮧ����� ���� ⥪��

  N78K_segstart,                // ��砫� ᥣ����
  std_gen_segm_footer,          // ����� ᥣ���� - �⠭�����, ��� �����襭��

  NULL,                         // ��४⨢� ᬥ�� ᥣ���� - �� �ᯮ�������

  N78K_ana,                     // ����������
  N78K_emu,                     // ����� ������権

  N78K_out,                     // ⥪�⮣������
  N78K_outop,                   // ⥪⮣������ ���࠭���
  N78K_data,                    // ������� ���ᠭ�� ������
  NULL,                         // �ࠢ������� ���࠭���
  NULL,                         // can have type

  qnumber(RegNames),            // Number of registers
  RegNames,                                             // Regsiter names
  NULL,                         // ������� ���祭�� ॣ����

  0,                            // �᫮ ॣ���஢�� 䠩���
  NULL,                         // ����� ॣ���஢�� 䠩���
  NULL,                         // ���ᠭ�� ॣ���஢
  NULL,                         // Pointer to CPU registers
  rVcs, rVds,
#if IDP_INTERFACE_VERSION > 37
  2,                            // size of a segment register
#endif
  rVcs, rVds,
  NULL,                         // ⨯��� ���� ��砫� �����
  retcodes,                     // ���� return'ov
#if IDP_INTERFACE_VERSION <= 37
  NULL,                         // �����頥� ����⭮��� ������� ��᫥����⥫쭮��
#endif
  0, NEC_78K_0_last,            // ��ࢠ� � ��᫥���� ������樨
  Instructions,                 // ���ᨢ �������� ������権
  NULL,                         // �஢�ઠ �� �������� ���쭥�� ���室�
#if IDP_INTERFACE_VERSION <= 37
  NULL,                         // ���஥��� �����稪
#endif
  NULL,                         // �࠭���� ᬥ饭��
  3,                            // ࠧ��� tbyte - 24 ���
  NULL,                         // �८�ࠧ���⥫� ������饩 �窨
  {0,0,0,0},                    // ����� ������ � ������饩 �窮�
  NULL,                         // ���� switch
  NULL,                         // ������� MAP-䠩��
  NULL,                         // ��ப� -> ����
  NULL,                         // �஢�ઠ �� ᬥ饭�� � �⥪�
  NULL,                         // ᮧ����� �३�� �㭪樨
  NULL,                                                 // Get size of function return address in bytes (2/4 by default)
  NULL,                         // ᮧ����� ��ப� ���ᠭ�� �⥪���� ��६�����
  NULL,                         // ������� ⥪�� ��� ....
  0,                            // Icode ��� ������� ������
  NULL,                         // ��।�� ��権 � IDP
  NULL,                         // Is the instruction created only for alignment purposes?
  NULL,                         // micro virtual mashine
  0                             // fixup bits
};
