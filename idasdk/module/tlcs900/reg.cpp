/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"
#include <diskio.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
// ᯨ᮪ ॣ���஢
static const char *const RegNames[] =
{
        // �㫥���
        "",
        // ���⮢� ॣ�����
        "W","A","B","C","D","E","H","L",
        // ᫮��� ॣ�����
        "WA","BC","DE","HL","IX","IY","IZ","SP",
        // ������� ᫮��
        "XWA","XBC","XDE","XHL","XIX","XIY","XIZ","XSP",
        // ����
        "IXL","IXH","IYL","IYH","IZL","IZH","SPL","SPH",
        // �ᥢ��-ᥣ����
        "cs","ds"
};

#if IDP_INTERFACE_VERSION > 37
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
  if ( code ) return code;

  switch ( msgid ){
    case processor_t::init:
      inf.mf = 0;
      inf.s_genflags |= INFFL_LZERO;
      helper.create("$ TLCS900");
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
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

    case processor_t::newprc:{
          char buf[MAXSTR];
          if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
            set_device_name(buf, IORESP_PORT);
        }
        break;

    case processor_t::newseg:{
                segment_t *s = va_arg(va, segment_t *);
                // Set default value of DS register for all segments
                set_default_dataseg(s->sel);
                }
                break;
  }
  va_end(va);
  return(1);
}
#else
// ���ᠭ�� �।��।������� ���ᮢ
typedef struct {
  uchar addr;   // ����
  char *name;   // ���
  char *cmt;    // ������਩
} predefined_t;


//----------------------------------------------------------------------
// ����७��� ॣ����� ������
static const predefined_t iregs[] = {
  { 0x00, "P0",         "Port 0" },
  { 0x01, "P1",         "Port 1" },
  { 0x02, "P0CR",       "Port 0 Control" },
  { 0x04, "P1CR",       "Port 1 Control" },
  { 0x05, "P1FC",       "Port 1 Function"},
  { 0x06, "P2",         "Port 2"},
  { 0x07, "P3",         "Port 3"},
  { 0x08, "P2CR",       "Port 2 Control"},
  { 0x09, "P2FC",       "Port 2 Function"},
  { 0x0A, "P3CR",       "Port 3 Control"},
  { 0x0B, "P3FC",       "Port 3 Function"},
  { 0x0C, "P4",         "Port 4"},
  { 0x0D, "P5",         "Port 5"},
  { 0x0E, "P4CR",       "Port 4 Control"},
  { 0x10, "P4FC",       "Port 4 Function"},
  { 0x12, "P6",         "Port 6"},
  { 0x13, "P7",         "Port 7"},
  { 0x14, "P6CR",       "Port 6 Control"},
  { 0x15, "P7CR",       "Port 7 Control"},
  { 0x16, "P6FC",       "Port 6 Function"},
  { 0x17, "P7FC",       "Port 7 Function"},
  { 0x18, "P8",         "Port 8"},
  { 0x19, "P9",         "Port 9"},
  { 0x1A, "P8CR",       "Port 8 Control"},
  { 0x1B, "P9CR",       "Port 9 Control"},
  { 0x1C, "P8FC",       "Port 8 Function"},
  { 0x1D, "P9FC",       "Port 9 Function"},
  { 0x1E, "PA",         "Port A"},
  { 0x1F, "PACR",       "Port A Control"},
  { 0x20, "TRUN",       "Timer Control"},
  { 0x22, "TREG0",      "Timer Register 0"},
  { 0x23, "TREG1",      "Timer Register 1"},
  { 0x24, "TMOD",       "Timer Source CLK & MODE"},
  { 0x25, "TFFCR",      "Flip-Flop Control"},
  { 0x26, "TREG2",      "Timer Register 2"},
  { 0x27, "TREG3",      "Timer Register 3"},
  { 0x28, "P0MOD",      "PWM0 Mode"},
  { 0x29, "P1MOD",      "PWM1 Mode"},
  { 0x2A, "PFFCR",      "PWM Flip-Flop Control"},
  { 0x30, "TREG4L",     "Timer Register 4 Low"},
  { 0x31, "TREG4H",     "Timer Register 4 High"},
  { 0x32, "TREG5L",     "Timer Register 5 Low"},
  { 0x33, "TREG5H",     "Timer Register 5 High"},
  { 0x34, "CAP1L",      "Capture Register 1 Low"},
  { 0x35, "CAP1H",      "Capture Register 1 High"},
  { 0x36, "CAP2L",      "Capture Register 2 Low"},
  { 0x37, "CAP2H",      "Capture Register 2 High"},
  { 0x38, "T4MOD",      "Timer 4 Source CLK & Mode"},
  { 0x39, "T4FFCR",     "Timer 4 Flip-Flop Control"},
  { 0x3A, "T45CR",      "T4, T5 Control"},
  { 0x40, "TREG6L",     "Timer Register 6 Low"},
  { 0x41, "TREG6H",     "Timer Register 6 High"},
  { 0x42, "TREG7L",     "Timer Register 7 Low"},
  { 0x43, "TREG7H",     "Timer Register 7 High"},
  { 0x44, "CAP3L",      "Capture Register 3 Low"},
  { 0x45, "CAP3H",      "Capture REgister 3 High"},
  { 0x46, "CAP4L",      "Capture Register 4 Low"},
  { 0x47, "CAP4H",      "Capture Register 4 High"},
  { 0x48, "T5MOD",      "Timer 5 Source CLK & Mode"},
  { 0x49, "T5FFCR",     "Timer 5 Flip-Flip Control"},
  { 0x50, "SC0BUF",     "Serial Chanel 0 Buffer"},
  { 0x51, "SC0CR",      "Serial Chanel 0 Control"},
  { 0x52, "SC0MOD",     "Serial Chanel 0 Mode"},
  { 0x53, "BR0CR",      "Serial Chanel 0 Baud Rate"},
  { 0x54, "SC1BUF",     "Serial Chanel 1 Buffer"},
  { 0x55, "SC1CR",      "Serial Chanel 1 Control"},
  { 0x56, "SC1MOD",     "Serial Chanel 1 Mode"},
  { 0x57, "BR1CR",      "Serial Chanel 1 Baud Rate"},
  { 0x58, "ODE",        "Serial Open Drain Enable"},
  { 0x5C, "WDMOD",      "Watch Dog Timer Mode"},
  { 0x5D, "WDCR",       "Watch Dog Control Register"},
  { 0x5E, "ADMOD1",     "A/D Mode Register 1"},
  { 0x5F, "ADMOD2",     "A/D Mode Register 2"},
  { 0x60, "ADREG04L",   "A/D Result Register 0/4 Low"},
  { 0x61, "ADREG04H",   "A/D Result Register 0/4 High"},
  { 0x62, "ADREG15L",   "A/D Result Register 1 Low"},
  { 0x63, "ADREG15H",   "A/D Result Register 1 High"},
  { 0x64, "ADREG26L",   "A/D Result Register 2 Low"},
  { 0x65, "ADREG26H",   "A/D Result Register 2 High"},
  { 0x66, "ADREG37L",   "A/D Result Register 3 Low"},
  { 0x67, "ADREG37H",   "A/D Result Register 3 High"},
  { 0x68, "B0CS",       "Block 0 CS/WAIT Control Register"},
  { 0x69, "B1CS",       "Block 1 CS/WAIT Control Register"},
  { 0x6A, "B2CS",       "Block 2 CS/WAIT Control Register"},
  { 0x6D, "CKOCR",      "Clock Output Control Register"},
  { 0x6E, "SYSCR0",     "System Clock Register 0"},
  { 0x6F, "SYSCR1",     "System Clock Contol Register 1"},
  { 0x70, "INTE0AD",    "Interrupt Enable 0 & A/D"},
  { 0x71, "INTE45",     "Interrupt Enable 4/5"},
  { 0x72, "INTE67",     "Interrupt Enable 6/7"},
  { 0x73, "INTET10",    "Interrupt Enable Timer 1/0"},
  { 0x74, "INTE89",     "Interrupt Enable 8/9"},
  { 0x75, "INTET54",    "Interrupt Enable 5/4"},
  { 0x76, "INTET76",    "Interrupt Enable 7/6"},
  { 0x77, "INTES0",     "Interrupt Enable Serial 0"},
  { 0x78, "INTES1",     "Interrupt Enable Serial 1"},
  { 0x7B, "IIMC",       "Interrupt Input Mode Control"},
  { 0x7C, "DMA0V",      "DMA 0 Reauest Vector"},
  { 0x7D, "DMA1V",      "DMA 1 Request Vector"},
  { 0x7E, "DMA2V",      "DMA 2 Request Vector"},
  { 0x7F, "DMA3V",      "DMA 3 Request Vector"},
  { 0x00,  NULL  ,  NULL }
};

//----------------------------------------------------------------------
// �஢���� ⥪�⮢�� ��� �� �।��।���������
static int IsPredefined(const char *name)
{
  const predefined_t *ptr;
  for ( ptr = iregs; ptr->name != NULL; ptr++ )
    if ( strcmp(ptr->name,name) == 0 ) return(1);
  return(0);
}

//----------------------------------------------------------------------
// ������� �� ����� ���
static const predefined_t *GetPredefined(predefined_t *ptr,uint32 addr)
{
  for ( ; ptr->name != NULL; ptr++ )
    if ( addr == ptr->addr )
      return(ptr);
  return(NULL);
}

//----------------------------------------------------------------------
// ᮧ���� �������� ᥣ���� �����. �����
static uint32 AdditionalSegment(int size,int offset,char *name)
{
  segment_t s;
  s.startEA = freechunk(0,size,0xF);
  s.endEA   = s.startEA + size;
  s.sel     = ushort((s.startEA-offset) >> 4);
  s.type    = SEG_IMEM;                         // internal memory
  add_segm(&s,name,NULL,ADDSEG_NOSREG);
  // ��୥� ��砫� ᥣ����
  return s.startEA - offset;
}

//----------------------------------------------------------------------
// �㭪�� �����饭��
static int idaapi notify(int msgnum,void *arg,...)
{ // Various messages:
  qnotused(arg);
  switch ( msgnum ) {
  // ���� 䠩�
  case IDP_NEWFILE:
      inf.mf = 0;                                       // MSB last
      inf.nametype = NM_SHORT;
      segment_t *sptr = get_first_seg();
      if ( sptr != NULL ) {
        if ( sptr->startEA-get_segm_base(sptr) == 0 ) {
          inf.beginEA = sptr->startEA;
          inf.startIP = 0;
        }
      }
      // �᭮���� ᥣ���� - ������
      set_segm_class(get_first_seg(),"CODE");
      // ᮧ����� ��� ���. ᥣ����
      AdditionalSegment(0x80,0,"SFR");         // ᥣ���� ॣ���஢
      AdditionalSegment(0x800,0x80,"INTMEM");  // ����ﭠ� ������
      // �ᯨ襬 ���� sfr ���⠬�
      for(ea_t ea=0;ea<0x80;ea++)doByte(ea,1);
      const predefined_t *ptr;
      // ᮧ����� �� ॣ����� � sfr'e � �ᯨ襬 �� �����
      for ( ptr=iregs; ptr->name != NULL; ptr++ ){
                ea_t ea = ptr->addr;
                ea_t oldea = get_name_ea(ptr->name);
                if ( oldea != ea ) {
                        // ���� ��㣮� ��� - ��६ ���
                        if ( oldea != BADADDR ) del_name(oldea);
                        // ��⠭���� ��� ���
                        set_name(ea,ptr->name);
                }
        // �᫨ ���� ������਩ - ���⠢�� ������਩
        if ( ptr->cmt != NULL ) set_cmt(ea,ptr->cmt,1);
      }
                break;
    // ᮧ����� ������ ᥣ����
    case IDP_NEWSEG:    {
                        segment_t *seg;
                        seg=((segment_t *)arg);
                        // ��⠭���� ॣ����� �� 㬮�砭��
                        seg->defsr[rVds-ph.regFirstSreg] = 0;
                        break;
                        }
  }
  return 1;
}
#endif

//-----------------------------------------------------------------------
//      Checkarg data. Common for all assemblers. Not good.
//-----------------------------------------------------------------------
static const char *operdim[15] = {  // ������ � ������ 15
     "(", ")", "!", "-", "+", "%",
     "\\", "/", "*", "&", "|", "^", "<<", ">>", NULL};
//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const asm_t pseudosam = {
  AS_COLON | AS_UDATA | ASH_HEXF3 ,
  // ���짮��⥫�᪨� 䫠���
  0,
  "Generic IAR-style assembler",        // �������� ��ᥬ����
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
  "DB",                                 // byte directive
  "DW",                                 // word directive
  "DL",                                 // dword  (4 bytes)
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
  "align"                               // ���� align
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
#define FAMILY "Toshiba TLCS-900 series:"
static const char *const shnames[] = { "TLCS900", NULL };
static const char *const lnames[] = { FAMILY"Toshiba TLCS900", NULL };

//--------------------------------------------------------------------------
// ���� �����⮢ �� �/�
static const uchar retcode_1[] = { 0x0E };    // ret
static const uchar retcode_2[] = { 0x0F };    // ret d
static const uchar retcode_3[] = { 0x07 };    // reti
static const bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH = {
  IDP_INTERFACE_VERSION,        // version
#if IDP_INTERFACE_VERSION > 37
  PLFM_TLCS900,                 // id ������
  PR_USE32|PR_BINMEM|PR_SEGTRANS|PR_DEFSEG32,      // can use register names for byte names
  8,                                                    // 8 bits in a byte for code segments
#else
  0x8001,
  PR_USE32|PR_DEFSEG32,         // can use register names for byte names
#endif
  8,                            // 8 bits in a byte

  shnames,                      // ���⪨� ����� �����஢ (�� 9 ᨬ�����)
  lnames,                       // ������ ����� �����஢

  asms,                         // ᯨ᮪ ��������஢

  notify,                       // �㭪�� �����饭��

  T900_header,                  // ᮧ����� ��������� ⥪��
  T900_footer,                  // ᮧ����� ���� ⥪��

  T900_segstart,                // ��砫� ᥣ����
  std_gen_segm_footer,          // ����� ᥣ���� - �⠭�����, ��� �����襭��

  NULL,                         // ��४⨢� ᬥ�� ᥣ���� - �� �ᯮ�������

  T900_ana,                     // ����������
  T900_emu,                     // ����� ������権

  T900_out,                     // ⥪�⮣������
  T900_outop,                   // ⥪⮣������ ���࠭���
  T900_data,                    // ������� ���ᠭ�� ������
  NULL,                         // �ࠢ������� ���࠭���
  NULL,                         // can have type

  qnumber(RegNames),            // Number of registers
  RegNames,                                             // Regsiter names
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
  0,T900_last,                  // ��ࢠ� � ��᫥���� ������樨
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
