/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"
#include <diskio.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
// ᯨ᮪ ॣ���஢
static const char *const RegNames[] =
{
  // �㫥���
  "",
  // ����� ॣ�����
  "A","X","Y",
  // �ᥢ��-ᥣ����
  "cs","ds"
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
  if ( code != 0 )
    return code;

  switch ( msgid )
  {
    case processor_t::init:
      inf.mf = 0;
      inf.s_genflags |= INFFL_LZERO;
      helper.create("$ C39");
    default:
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
  }
  va_end(va);
  return(1);
}
//-----------------------------------------------------------------------
//      Checkarg data. Common for all assemblers. Not good.
//-----------------------------------------------------------------------
static const char *operdim[15] = // ������ � ������ 15
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
  // ���짮��⥫�᪨� 䫠���
  0,
  "Generic C39 assembler",              // �������� ��ᥬ����
  0,                                    // ����� � help'e
  NULL,                                 // ��⮧��������
  NULL,                                 // ���ᨢ �� �ᯮ������� ������権
  "org",                                // ��४⨢� ORG
  "end",                                // ��४⨢� end

  ";",                                  // ������਩
  '"',                                  // ࠧ����⥫� ��ப�
  '\'',                                 // ᨬ���쭠� ����⠭�
  "\\\"'",                              // ᯥ�ᨬ����

  "db",                                 // ascii string directive
  ".DATA.B",                             // byte directive
  ".DATA.W",                             // word directive
  ".DATA.L",                             // dword  (4 bytes)
  NULL,                                 // qword  (8 bytes)
#if IDP_INTERFACE_VERSION > 37
  NULL,     // oword  (16 bytes)
#endif
  NULL,                                 // float  (4 bytes)
  NULL,                                 // double (8 bytes)
  NULL,                                 // tbyte  (10/12 bytes)
  NULL,                                 // packed decimal real
  "#d dup(#v)",                         // arrays (#h,#d,#v,#s(...)
  "db ?",                               // uninited arrays
  ".equ",                               // equ
  NULL,                                 // seg prefix
  NULL,                              // ����஫�
  NULL,                                 // atomprefix
  operdim,                              // ���ᨢ ����権
  NULL,                                 // ��४���஢�� � ASCII
  "$",                                  // ����騩 IP
  NULL,                                 // ��������� �㭪樨
  NULL,                                 // ����� �㭪樨
  NULL,                                 // ��४⨢� public
  NULL,                                 // ��४⨢� weak
  NULL,                                 // ��४⨢� extrn
  NULL,                                 // ��४⨢� comm
  NULL,                                 // ������� ��� ⨯�
  ".ALIGN"                              // ���� align
#if IDP_INTERFACE_VERSION > 37
  ,'(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
#endif
};

// ���᮪ ��ᥬ���஢
static const asm_t *const asms[] = { &pseudosam, NULL };
//-----------------------------------------------------------------------
#define FAMILY "Rockwell C39:"
static const char *const shnames[] = { "C39", NULL };
static const char *const lnames[] = { FAMILY"Rockwell C39", NULL };

//--------------------------------------------------------------------------
// ���� �����⮢ �� �/�
static const uchar retcode_1[] = { 0x00, 0x0B };    // RTS
static const bytes_t retcodes[] =
{
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_C39,                     // id ������
#if IDP_INTERFACE_VERSION > 37
  PR_USE32|PR_BINMEM|PR_SEGTRANS,      // can use register names for byte names
  8,                                                    // 8 bits in a byte for code segments
#else
  PR_USE32,         // can use register names for byte names
#endif
  8,                            // 8 bits in a byte

  shnames,                      // ���⪨� ����� �����஢ (�� 9 ᨬ�����)
  lnames,                       // ������ ����� �����஢

  asms,                         // ᯨ᮪ ��������஢

  notify,                       // �㭪�� �����饭��

  C39_header,                   // ᮧ����� ��������� ⥪��
  C39_footer,                   // ᮧ����� ���� ⥪��

  C39_segstart,                 // ��砫� ᥣ����
  std_gen_segm_footer,          // ����� ᥣ���� - �⠭�����, ��� �����襭��

  NULL,                         // ��४⨢� ᬥ�� ᥣ���� - �� �ᯮ�������

  C39_ana,                      // ����������
  C39_emu,                      // ����� ������権

  C39_out,                      // ⥪�⮣������
  C39_outop,                    // ⥪⮣������ ���࠭���
  C39_data,                     // ������� ���ᠭ�� ������
  NULL,                         // �ࠢ������� ���࠭���
  NULL,                         // can have type

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Regsiter names
  NULL,                         // ������� ���祭�� ॣ����

  0,                            // �᫮ ॣ���஢�� 䠩���
  NULL,                         // ����� ॣ���஢�� 䠩���
  NULL,                         // ���ᠭ�� ॣ���஢
  NULL,                         // Pointer to CPU registers
  rVcs,rVds,
#if IDP_INTERFACE_VERSION > 37
  2,                            // size of a segment register
#endif
  rVcs,rVds,
  NULL,                         // ⨯��� ���� ��砫� �����
  retcodes,                     // ���� return'ov
#if IDP_INTERFACE_VERSION <= 37
  NULL,                         // �����頥� ����⭮��� ������� ��᫥����⥫쭮��
#endif
  0,C39_last,                   // ��ࢠ� � ��᫥���� ������樨
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
#if IDP_INTERFACE_VERSION > 37
  NULL,                                                 // Get size of function return address in bytes (2/4 by default)
#endif
  NULL,                         // ᮧ����� ��ப� ���ᠭ�� �⥪���� ��६�����
  NULL,                         // ������� ⥪�� ��� ....
  0,                            // Icode ��� ������� ������
  NULL,                         // ��।�� ��権 � IDP
  NULL,                                                 // Is the instruction created only for alignment purposes?
  NULL                          // micro virtual mashine
#if IDP_INTERFACE_VERSION > 37
  ,0                                                    // fixup bit's
#endif
};
