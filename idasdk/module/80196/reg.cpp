/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"

//--------------------------------------------------------------------------
// ����� �� �����, �� ��� ᤥ���� ���� ���� � ������ �����?
// ig: �����. ����� ��������ﬨ �뢥��, � append_cmt()
static const predefined_t iregs[] =
{
  { 0x00, "ZERO_REG",  "Zero register" },
  { 0x08, "INT_MASK",  "Interrupt mask register" },
  { 0x09, "INT_PEND",  "Interrupt pending register" },
  { 0x0F, "IOPORT1",   "Input/output port 1" },
  { 0x10, "IOPORT2",   "Input/output port 2" },
  { 0x12, "INT_PEND1", "Interrupt pending register 1" },
  { 0x13, "INT_MASK1", "Interrupt mask register 1" },
  { 0x14, "WSR",       "Window selection register" },
  { 0x15, "WSR1",      "Window selection register 1" },
  { 0x18, "SP",        "Stack pointer" },
  { 0x00, NULL, NULL }
};

//--------------------------------------------------------------------------
/* 80196 memory map
 *
 * 0000-03FF - register file
 *   0000    - CPU SFRs
 *   0018    - SP (LO)
 *   0019    - SP (HI)
 *   001A    - Register RAM
 *   0100    - Register RAM (upper file)
 * 0400-1FFD - ext memory
 * 1FFE      - port 3 (word)
 * 1FFF      - port 4 (word)
 * 2000-207F - special purpose memory
 *   2000    - lower int vectors
 *     2000  - INT00 - Timer overflow
 *     2002  - INT01 - A/D conversion complete
 *     2004  - INT02 - HSI data available
 *     2006  - INT03 - High speed output
 *     2008  - INT04 - HSI.0
 *     200A  - INT05 - Software timer
 *     200C  - INT06 - Serial port
 *     200E  - INT07 - EXTINT
 *     2010  - Software trap
 *     2012  - Unimplemented opcode
 *   2014    - reserved (FF)
 *   2018    - CCB
 *             D0  - PD  - Power down
 *             D1  - BW0 - Bus width control
 *             D2  - WR  - Write strobe mode
 *             D3  - ALE - Addres valid strobe mode
 *             D45 - IRC - Internal ready control
 *             D67 - LOC - Lock bits
 *   2019    - reserved (20)
 *   201A    - reserved (FF)
 *   2020    - security key
 *   2030    - upper int vectors
 *     2030  - INT08 - Transmit
 *     2032  - INT09 - Receive
 *     2034  - INT10 - HSI FIFO 4
 *     2036  - INT11 - Timer 2 capture
 *     2038  - INT12 - Timer 2 overflow
 *     203A  - INT13 - EXTINT1
 *     203C  - INT14 - HSI FIFO FULL
 *     203E  - INT15 - NMI
 *   2040    - PTS vectors
 *     2040  - INT00 - Timer overflow
 *     2042  - INT01 - A/D conversion complete
 *     2044  - INT02 - HSI data available
 *     2046  - INT03 - High speed output
 *     2048  - INT04 - HSI.0
 *     204A  - INT05 - Software timer
 *     204C  - INT06 - Serial port
 *     204E  - INT07 - EXTINT
 *     2050  - INT08 - Transmit
 *     2052  - INT09 - Receive
 *     2054  - INT10 - HSI FIFO 4
 *     2056  - INT11 - Timer 2 capture
 *     2058  - INT12 - Timer 2 overflow
 *     205A  - INT13 - EXTINT1
 *     205C  - INT14 - HSI FIFO FULL
 *   205E    - reserved (FF)
 * 2080-FFFF - program/ext memory
 */

#define I196F_CMT 0   // global comment
#define I196F_OFF 1   // offset to code
#define I196F_BTS 2   // byte(s)

struct entry_t
{
  char type;
  int off;      //lint !e958 padding is required to align members
  const char *name;
  const char *cmt;
};

static const char cmt01[] = "Timer overflow";
static const char cmt02[] = "A/D conversion complete";
static const char cmt03[] = "HSI data available";
static const char cmt04[] = "High speed output";
static const char cmt05[] = "HSI.0";
static const char cmt06[] = "Software timer";
static const char cmt07[] = "Serial port";
static const char cmt08[] = "EXTINT";
static const char cmt09[] = "reserved (FF)";
static const char cmt10[] = "Transmit";
static const char cmt11[] = "Receive";
static const char cmt12[] = "HSI FIFO 4";
static const char cmt13[] = "Timer 2 capture";
static const char cmt14[] = "Timer 2 overflow";
static const char cmt15[] = "EXTINT1";
static const char cmt16[] = "HSI FIFO FULL";

static entry_t const entries[] =
{
//�� ࠢ�� �� �뢮����� ��� ���� :-(
//  { I196F_CMT, 0x2000, 0,           "\nlower int vectors\n" },

  { I196F_OFF, 0x2000, "Int00",     cmt01 },
  { I196F_OFF, 0x2002, "Int01",     cmt02 },
  { I196F_OFF, 0x2004, "Int02",     cmt03 },
  { I196F_OFF, 0x2006, "Int03",     cmt04 },
  { I196F_OFF, 0x2008, "Int04",     cmt05 },
  { I196F_OFF, 0x200A, "Int05",     cmt06 },
  { I196F_OFF, 0x200C, "Int06",     cmt07 },
  { I196F_OFF, 0x200E, "Int07",     cmt08 },
  { I196F_OFF, 0x2010, "Trap",      "Software trap" },
  { I196F_OFF, 0x2012, "NoOpCode",  "Unimplemented opcode" },

  { I196F_CMT, 0x2014, 0,           0 },    // empty line

  { I196F_BTS, 0x2014, 0,           cmt09 },
  { I196F_BTS, 0x2018, "CCB",       "D0  - PD  - Power down\n"
                                    "D1  - BW0 - Bus width control\n"
                                    "D2  - WR  - Write strobe mode\n"
                                    "D3  - ALE - Addres valid strobe mode\n"
                                    "D45 - IRC - Internal ready control\n"
                                    "D67 - LOC - Lock bits" },
  { I196F_BTS, 0x2019, 0,           "reserved (20)" },
  { I196F_BTS, 0x201A, 0,           cmt09 },
  { I196F_BTS, 0x2020, 0,           "security key" },

  { I196F_CMT, 0x2030, 0,           "\nupper int vectors\n" },

  { I196F_OFF, 0x2030, "Int08",     cmt10 },
  { I196F_OFF, 0x2032, "Int09",     cmt11 },
  { I196F_OFF, 0x2034, "Int10",     cmt12 },
  { I196F_OFF, 0x2036, "Int11",     cmt13 },
  { I196F_OFF, 0x2038, "Int12",     cmt14 },
  { I196F_OFF, 0x203A, "Int13",     cmt15 },
  { I196F_OFF, 0x203C, "Int14",     cmt16 },
  { I196F_OFF, 0x203E, "Int15",     "NMI" },

  { I196F_CMT, 0x2040, 0,           "\nPTS vectors\n" },

  { I196F_OFF, 0x2040, "PTS_Int00", cmt01 },
  { I196F_OFF, 0x2042, "PTS_Int01", cmt02 },
  { I196F_OFF, 0x2044, "PTS_Int02", cmt03 },
  { I196F_OFF, 0x2046, "PTS_Int03", cmt04 },
  { I196F_OFF, 0x2048, "PTS_Int04", cmt05 },
  { I196F_OFF, 0x204A, "PTS_Int05", cmt06 },
  { I196F_OFF, 0x204C, "PTS_Int06", cmt07 },
  { I196F_OFF, 0x204E, "PTS_Int07", cmt08 },
  { I196F_OFF, 0x2050, "PTS_Int08", cmt10 },
  { I196F_OFF, 0x2052, "PTS_Int09", cmt11 },
  { I196F_OFF, 0x2054, "PTS_Int10", cmt12 },
  { I196F_OFF, 0x2056, "PTS_Int11", cmt13 },
  { I196F_OFF, 0x2058, "PTS_Int12", cmt14 },
  { I196F_OFF, 0x205A, "PTS_Int13", cmt15 },
  { I196F_OFF, 0x205C, "PTS_Int14", cmt16 },

  { I196F_CMT, 0x205E, 0,           0 },

  { I196F_BTS, 0x205E, 0,           cmt09 },

//  { I196F_CMT, 0x2080, 0,           "\nProgram entry point\n" },

  { I196F_CMT, 0x2080, 0,           0 }
};

//--------------------------------------------------------------------------
static const char *const RegNames[] = { "cs", "ds", "WSR", "WSR1" };
int extended = 0;

//--------------------------------------------------------------------------
static int idaapi notify(processor_t::idp_notify msgid, ...)   // Various messages
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
    case processor_t::newfile:
      {
// ig: ����� � ���� ⥯��� ⠪�� �窠 �७��:
//     �� ���� � ���� �������� ��� ����.
//     �� ������� �� ����� ᤥ���� � ida.cfg:
//      #ifdef __80196__
//        DUMMY_NAMES_TYPE = NM_SHORT
//      #endif

        segment_t *sptr = get_first_seg();
        if( sptr != NULL )    set_segm_class( sptr, "CODE" );

        ea_t ea, ea1;

        for( int i = 0; i < qnumber(entries); i++ )
        {
          ea = toEA( inf.baseaddr, entries[i].off );

          if( isEnabled(ea) )
          {
            switch( entries[i].type )
            {
              case I196F_BTS:
                if ( i < qnumber(entries)-1 )
                {
                  doByte( ea, entries[i+1].off-entries[i].off );
                  set_cmt( ea, entries[i].cmt, 0 );
                }
                break;

              case I196F_CMT:
                if( entries[i].cmt )
                  add_long_cmt( ea, 1, "%s", entries[i].cmt );
                else
                  describe( ea, 1, "" );
                break;

              case I196F_OFF:
                doWord( ea, 2 );
                set_offset( ea, 0, toEA( inf.baseaddr, 0 ) );

                ea1 = toEA( inf.baseaddr, get_word( ea ) );
                auto_make_proc( ea1 );
//dash: long_cmt ����� �� ᬮ�����, ⠪ ��� ������ �� ���������
//      ��� �� ���⠢��� func_cmt, �� � �⮬� ������� �㭪権 �� ���
//      ��� ����?
//ig: ��ᯮ�짮������ ����� �������ਥ�
//    �� ᮧ����� �㭪樨 �������਩ ��������
                set_cmt( ea1, entries[i].cmt, 1 );
            }

            set_name( ea, entries[i].name );
          }
        }

        ea = toEA( inf.baseaddr, 0x2080 );
        if( isEnabled( ea ) )
        {
          inf.beginEA = ea;
          inf.startIP = 0x2080;
        }

        segment_t s;
        s.startEA = toEA( inf.baseaddr, 0 );
        s.endEA   = toEA( inf.baseaddr, 0x400 );
        s.sel     = inf.baseaddr;
        s.type    = SEG_IMEM;                         // internal memory
// ig: ���� �᪠�� ���� �� �� ���, � �� ���� ����㧪�
//      ea_t bottom = toEA( inf.baseaddr, 0 );
//      intmem    = s.startEA = freechunk( bottom, 1024, 0xF );
//      s.endEA   = s.startEA + 1024;
//      s.sel     = ushort(s.startEA >> 4);
// dash: ���� �᪠�� �� ��諮��, �� � ��⠢�� �� ��� �ਬ�� �� ���饥
        add_segm_ex( &s, "INTMEM", NULL, ADDSEG_OR_DIE);

        const predefined_t *ptr;
        for ( ptr = iregs; ptr->name != NULL; ptr++ )
        {
          ea = toEA(inf.baseaddr, ptr->addr);
          ea_t oldea = get_name_ea( BADADDR, ptr->name );
          if ( oldea != ea )
          {
            if ( oldea != BADADDR )
              set_name( oldea, NULL );
            do_unknown( ea, DOUNK_EXPAND );
            set_name( ea, ptr->name );
          }
          if ( ptr->cmt != NULL )
            set_cmt( ea, ptr->cmt, 1 );
        }
      }
//      do16bit( 0x18, 2 );           // SP always word
      break;

    case processor_t::newseg:
                      // default DS is equal to Base Address
      (va_arg(va, segment_t *))->defsr[rVds-ph.regFirstSreg] = inf.baseaddr;
      break;

    case processor_t::newprc:
      extended = va_arg(va,int) != 0;
      if ( !extended )
        ph.flag &= ~PR_SEGS;
      else
        ph.flag |= PR_SEGS;
    default:
      break;
  }
  va_end(va);

  return(1);
}

//--------------------------------------------------------------------------
//!!! ��, ��� �� �� ��ᥬ���� �����...
// ig: ��, ��� ��ᥬ���� ����.
//     ������ ���� �⮩ �������� ������⭮ ��� ���������,
//     �.�. �������⭮, ��� ࠡ�⠥� ��ᥬ����.
//     �� �⮦, ᤥ��� ⠪, ��� ⥡� ����� �ࠢ����
static const asm_t unkasm =
{
  AS_COLON | ASH_HEXF0,
  0,
  "Abstract Assembler",
  0,
  NULL,
  NULL,
  "org",
  "end",

  ";",      // comment string
  '\'',     // string delimiter
  '\0',     // char delimiter (no char consts)
  "\\\"'",  // special symbols in char and string constants

  "db",     // ascii string directive
  "db",     // byte directive
  "dw",     // word directive
  "dd",     // dword  (4 bytes)
  NULL,     // qword  (8 bytes)
  NULL,     // oword  (16 bytes)
  NULL,     // float  (4 bytes)
  NULL,     // double (8 bytes)
  NULL,     // tbyte  (10/12 bytes)
  NULL,     // packed decimal real
  NULL,     // arrays (#h,#d,#v,#s(...)
  "ds %s",  // uninited arrays
  "equ",    // Equ
  NULL,     // seg prefix
  NULL, NULL, NULL,     // checkarg is not present in this module
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
  "and",   // and
  "or",    // or
  NULL,    // xor
  "not",   // not
  NULL,    // shl
  NULL,    // shr
  "SIZE",  // sizeof
};

static const asm_t *const asms[] = { &unkasm, NULL };

//--------------------------------------------------------------------------
#define FAMILY "Intel 196 series:"
static const char *const shnames[] = { "80196", "80196NP", NULL };
static const char *const lnames[]  = { FAMILY"Intel 80196", "Intel 80196NP", NULL };

//--------------------------------------------------------------------------
static const uchar retcode[] = { 0xF0 };  // ret

static const bytes_t retcodes[] =
{
 { sizeof( retcode ), retcode },
 { 0, NULL }
};

//------------------------------------------------------------------------
static bool idaapi can_have_type(op_t &x)      // returns 1 - operand can have
{
  switch ( x.type )
  {
    case o_void:
    case o_reg:
    case o_indirect:
    case o_indirect_inc:
    case o_bit:
    case o_mem:
    case o_near:
      return 0;
//    case o_phrase: can have type because of ASI or 0 struct offsets
  }
  return 1;
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------

processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_80196,             // id
  PRN_HEX|PR_USE32|PR_SEGS|PR_BINMEM|PR_RNAMESOK,
  8,                    // 8 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,    // short processor names (null term)
  lnames,     // long processor names (null term)

  asms,       // array of enabled assemblers

  notify,     // Various messages:

  header,     // produce start of text file
  footer,     // produce end of text file

  segstart,   // produce start of segment
  segend,     // produce end of segment

  NULL,

  ana,
  emu,

  out,
  outop,
//!!! ������ ���� ᢮� �㭪�� ???
// ig: ���, ����易⥫쭮.
//     �� ������� ����� ᤥ���� ᢮�, �᫨ intel_data 祬 ����� �� ���ࠨ����
  intel_data,   //i196_data,
  NULL,         // compare operands
  can_have_type,        // can have type
  qnumber(RegNames),    // Number of registers
  RegNames,             // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,WSR1,
  2,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0, I196_last,
  Instructions
};
