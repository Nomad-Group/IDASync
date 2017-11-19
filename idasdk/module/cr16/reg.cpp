
/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"
#include <diskio.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
// list of registers
static const char *const RegNames[] =
{
  // empty
  "",
  // general purpose
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "r12", "r13", "ra", "sp",
  // special
  "pc", "isp", "intbase", "psr", "cfg", "dsr", "dcr", "carl", "carh",
  "intbaseh", "intbasel",

  // pseudo segments
  "cs", "ds"
};

static netnode helper;
char device[MAXSTR] = "";
static size_t numports = 0;
static ioport_t *ports = NULL;

#include "../iocommon.cpp"

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

  if (code)
    return code;

  switch (msgid)
  {
    case processor_t::init:
      inf.mf = 0;
      inf.s_genflags |= INFFL_LZERO;
      helper.create("$ CR16");
    default:
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::newfile:
      // ask for a  processor from the config file
      // use it to handle ports and registers
      {
        char cfgfile[QMAXFILE];

        get_cfg_filename(cfgfile, sizeof(cfgfile));
        if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
          set_device_name(device, IORESP_ALL);
      }
      break;

    case processor_t::newprc:
      {
        char buf[MAXSTR];
        if (helper.supval(-1, buf, sizeof(buf)) > 0)
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
  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
//      Checkarg data. Common for all assemblers. Not good.
//-----------------------------------------------------------------------
static const char *operdim[15] = // always strictly 15
{
  "(", ")", "!", "-", "+", "%",
  "\\", "/", "*", "&", "|", "^", "<<", ">>", NULL
};

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const asm_t pseudosam =
{
  AS_COLON | AS_UDATA | ASH_HEXF3 | ASD_DECF0,
  // user flags
  0,
  "Generic CR16 assembler",     // title
  0,                            // help id
  NULL,                         // header
  NULL,                         // not used instructions
  "org",                        // ORG directive
  "end",                        // end directive

  ";",                          // comment
  '"',                          // string delimiter
  '\'',                         // character constant
  "\\\"'",                      // special characters

  "db",                         // ascii string directive
  ".byte",                      // byte directive
  ".word",                      // word directive
  NULL,                         // dword  (4 bytes)
  NULL,                         // qword  (8 bytes)
  NULL,                         // oword  (16 bytes)
  NULL,                         // float  (4 bytes)
  NULL,                         // double (8 bytes)
  NULL,                         // tbyte  (10/12 bytes)
  NULL,                         // packed decimal real
  "#d dup(#v)",                 // arrays (#h,#d,#v,#s(...)
  "db ?",                       // uninited arrays
  ".equ",                       // equ
  NULL,                         // seg prefix
  NULL,                         // ����஫�
  NULL,                         // atomprefix
  operdim,                      // ���ᨢ ����権
  NULL,                         // ��४���஢�� � ASCII
  "$",                          // ����騩 IP
  NULL,                         // ��������� �㭪樨
  NULL,                         // ����� �㭪樨
  NULL,                         // ��४⨢� public
  NULL,                         // ��४⨢� weak
  NULL,                         // ��४⨢� extrn
  NULL,                         // ��४⨢� comm
  NULL,                         // ������� ��� ⨯�
  ".ALIGN",                     // ���� align
  '(', ')',                     // lbrace, rbrace
  NULL,                         // mod
  NULL,                         // and
  NULL,                         // or
  NULL,                         // xor
  NULL,                         // not
  NULL,                         // shl
  NULL,                         // shr
  NULL,                         // sizeof
};

// list of assemblers
static const asm_t *const asms[] = { &pseudosam, NULL };

//-----------------------------------------------------------------------
#define FAMILY "NSC CR16:"

// short names
static const char *const shnames[] = { "CR16", NULL };

// long names
static const char *const lnames[] = { FAMILY"NSC CR16", NULL };

//--------------------------------------------------------------------------
// return instructions
static const uchar retcode_1[] = { 0x00, 0x0B };      // RTS

static const bytes_t retcodes[] =
{
  {sizeof(retcode_1), retcode_1},
  {0, NULL}
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_CR16,                    // processor ID
  PR_USE32 | PR_BINMEM | PR_SEGTRANS,   // can use register names for byte names
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for data segments

  shnames,                      // ���⪨� ����� �����஢ (�� 9 ᨬ�����)
  lnames,                       // ������ ����� �����஢

  asms,                         // ᯨ᮪ ��������஢

  notify,                       // �㭪�� �����饭��

  CR16_header,                  // ᮧ����� ��������� ⥪��
  CR16_footer,                  // ᮧ����� ���� ⥪��

  CR16_segstart,                // ��砫� ᥣ����
  std_gen_segm_footer,          // ����� ᥣ���� - �⠭�����, ��� �����襭��

  NULL,                         // ��४⨢� ᬥ�� ᥣ���� - �� �ᯮ�������

  CR16_ana,                     // ����������
  CR16_emu,                     // ����� ������権

  CR16_out,                     // ⥪�⮣������
  CR16_outop,                   // ⥪⮣������ ���࠭���
  CR16_data,                    // ������� ���ᠭ�� ������
  NULL,                         // �ࠢ������� ���࠭���
  NULL,                         // can have type

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Regsiter names
  NULL,                         // ������� ���祭�� ॣ����

  0,                            // �᫮ ॣ���஢�� 䠩���
  NULL,                         // ����� ॣ���஢�� 䠩���
  NULL,                         // ���ᠭ�� ॣ���஢
  NULL,                         // Pointer to CPU registers
  rVcs, rVds,
  2,                            // size of a segment register
  rVcs, rVds,
  NULL,                         // ⨯��� ���� ��砫� �����
  retcodes,                     // ���� return'ov
  0, CR16_last,                 // ��ࢠ� � ��᫥���� ������樨
  Instructions,                 // ���ᨢ �������� ������権
  NULL,                         // �஢�ઠ �� �������� ���쭥�� ���室�
  NULL,                         // �࠭���� ᬥ饭��
  3,                            // ࠧ��� tbyte - 24 ���
  NULL,                         // �८�ࠧ���⥫� ������饩 �窨
  {0, 0, 0, 0},                 // ����� ������ � ������饩 �窮�
  NULL,                         // ���� switch
  NULL,                         // ������� MAP-䠩��
  NULL,                         // ��ப� -> ����
  NULL,                         // �஢�ઠ �� ᬥ饭�� � �⥪�
  NULL,                         // ᮧ����� �३�� �㭪樨
  NULL,                         // Get size of function return address in bytes (2/4 by default)
  NULL,                         // ᮧ����� ��ப� ���ᠭ�� �⥪���� ��६�����
  NULL,                         // ������� ⥪�� ��� ....
  0,                            // Icode ��� ������� ������
  NULL,                         // ��।�� ��権 � IDP
  NULL,                         // Is the instruction created only for alignment purposes?
  NULL,                         // micro virtual mashine
  0                             // fixup bit's
};
