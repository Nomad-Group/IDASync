
#include "st9.hpp"

//--------------------------------------------------------------------------
// Get description for a given general register.
// Description may change according to the current number of the registers page.
static const char *get_general_register_description(const ushort reg)
{
  if ( reg < rR240 || reg > rR255 )
    return NULL;

  switch ( get_segreg(cmd.ea, rRP) )
  {
    // page: N/A
    case BADSEL:
      switch ( reg )
      {
        case rR230:     return "Central Interrupt Control Register";
        case rR231:     return "Flag Register";
        case rR232:     return "Pointer 0 Register";
        case rR233:     return "Pointer 1 Register";
        case rR234:     return "Page Pointer Register";
        case rR235:     return "Mode Register";
        case rR236:     return "User Stack Pointer High Register";
        case rR237:     return "User Stack Pointer Low Register";
        case rR238:     return "System Stack Pointer High Register";
        case rR239:     return "System Stack Pointer Low Register";
      }
      break;

    // page: 0
    case 0:
      switch ( reg )
      {
        case rR241:     return "Minor Register";
        case rR242:     return "External Interrupt Trigger Register";
        case rR243:     return "External Interrupt Pending Register";
        case rR244:     return "External Interrupt Mask-bit Register";
        case rR245:     return "External Interrupt Priority Level Register";
        case rR246:     return "External Interrupt Vector Register";
        case rR247:     return "Nested Interrupt Control";
        case rR248:     return "Watchdog Timer High Register";
        case rR249:     return "Watchdog Timer Low Register";
        case rR250:     return "Watchdog Timer Prescaler Register";
        case rR251:     return "Watchdog Timer Control Register";
        case rR252:     return "Wait Control Register";
        case rR253:     return "SPI Data Register";
        case rR254:     return "SPI Control Register";
      }
      break;

    // page: 2
    case 2:
      switch ( reg )
      {
        case rR240:     return "Port 0 Configuration Register 0";
        case rR241:     return "Port 0 Configuration Register 1";
        case rR242:     return "Port 0 Configuration Register 2";
        case rR244:     return "Port 1 Configuration Register 0";
        case rR245:     return "Port 1 Configuration Register 1";
        case rR246:     return "Port 1 Configuration Register 2";
        case rR248:     return "Port 2 Configuration Register 0";
        case rR249:     return "Port 2 Configuration Register 1";
        case rR250:     return "Port 2 Configuration Register 2";
      }
      break;

    // page: 3
    case 3:
      switch ( reg )
      {
        case rR240:     return "Port 4 Configuration Register 0";
        case rR241:     return "Port 4 Configuration Register 1";
        case rR242:     return "Port 4 Configuration Register 2";
        case rR244:     return "Port 5 Configuration Register 0";
        case rR245:     return "Port 5 Configuration Register 1";
        case rR246:     return "Port 5 Configuration Register 2";
        case rR248:     return "Port 6 Configuration Register 0";
        case rR249:     return "Port 6 Configuration Register 1";
        case rR250:     return "Port 6 Configuration Register 2";
        case rR251:     return "Port 6 Data Register";
        case rR252:     return "Port 7 Configuration Register 0";
        case rR253:     return "Port 7 Configuration Register 1";
        case rR254:     return "Port 7 Configuration Register 2";
        case rR255:     return "Port 7 Data Register";
      }
      break;

    // page: 8, 10 or 12
    case 8:
    case 10:
    case 12:
      switch ( reg )
      {
        case rR240:     return "Capture Load Register 0 High";
        case rR241:     return "Capture Load Register 0 Low";
        case rR242:     return "Capture Load Register 1 High";
        case rR243:     return "Capture Load Register 1 Low";
        case rR244:     return "Compare 0 Register High";
        case rR245:     return "Compare 0 Register Low";
        case rR246:     return "Compare 1 Register High";
        case rR247:     return "Compare 1 Register Low";
        case rR248:     return "Timer Control Register";
        case rR249:     return "Timer Mode Register";
        case rR250:     return "External Input Control Register";
        case rR251:     return "Prescaler Register";
        case rR252:     return "Output A Control Register";
        case rR253:     return "Output B Control Register";
        case rR254:     return "Flags Register";
        case rR255:     return "Interrupt/DMA Mask Register";
      }
      break;

    // page: 9
    case 9:
      switch ( reg )
      {
        case rR240:
        case rR244:     return "DMA Counter Pointer Register";
        case rR241:
        case rR245:     return "DMA Address Pointer Register";
        case rR242:
        case rR246:     return "Interrupt Vector Register";
        case rR243:
        case rR247:     return "Interrupt/DMA Control Register";
        case rR248:     return "I/O Connection Register";
      }
      break;

    // page: 11
    case 11:
      switch ( reg )
      {
        case rR240:     return "Counter High Byte Register";
        case rR241:     return "Counter Low Byte Register";
        case rR242:     return "Standard Timer Prescaler Register";
        case rR243:     return "Standard Timer Control Register";
      }
      break;

    // page: 13
    case 13:
      switch ( reg )
      {
        case rR244:     return "DMA Counter Pointer Register";
        case rR245:     return "DMA Address Pointer Register";
        case rR246:     return "Interrupt Vector Register";
        case rR247:     return "Interrupt/DMA Control Register";
      }
      break;

    // page: 21
    case 21:
      switch ( reg )
      {
        case rR240:     return "Data Page Register 0";
        case rR241:     return "Data Page Register 1";
        case rR242:     return "Data Page Register 2";
        case rR243:     return "Data Page Register 3";
        case rR244:     return "Code Segment Register";
        case rR248:     return "Interrupt Segment Register";
        case rR249:     return "DMA Segment Register";
        case rR245:     return "External Memory Register 1";
        case rR246:     return "External Memory Register 2";
      }
      break;

    // page: 24 or 25
    case 24:
    case 25:
      switch ( reg )
      {
        case rR240:     return "Receiver DMA Transaction Counter Pointer";
        case rR241:     return "Receiver DMA Source Address Pointer";
        case rR242:     return "Transmitter DMA Transaction Counter Pointer";
        case rR243:     return "Transmitter DMA Source Address Pointer";
        case rR244:     return "Interrupt Vector Register";
        case rR245:     return "Address/Data Compare Register";
        case rR246:     return "Interrupt Mask Register";
        case rR247:     return "Interrupt Status Register";
        case rR248:     return "Receive/Transmitter Buffer Register";
        case rR249:     return "Interrupt/DMA Priority Register";
        case rR250:     return "Character Configuration Register";
        case rR251:     return "Clock Configuration Register";
        case rR252:     return "Baud Rate Generator High Register";
        case rR253:     return "Baud Rate Generator Low Register";
        case rR254:     return "Synchronous Input Control";
        case rR255:     return "Synchronous Output Control";
      }
      break;

    // page: 43
    case 43:
      switch ( reg )
      {
        case rR248:     return "Port 8 Configuration Register 0";
        case rR249:     return "Port 8 Configuration Register 1";
        case rR250:     return "Port 8 Configuration Register 2";
        case rR251:     return "Port 8 Data Register";
        case rR252:     return "Port 9 Configuration Register 0";
        case rR253:     return "Port 9 Configuration Register 1";
        case rR254:     return "Port 9 Configuration Register 2";
        case rR255:     return "Port 9 Data Register";
      }
      break;

    // page: 55
    case 55:
      switch ( reg )
      {
        case rR240:     return "Clock Control Register";
        case rR242:     return "Clock Flag Register";
        case rR246:     return "PLL Configuration Register";
      }
      break;

    // page: 63
    case 63:
      switch ( reg )
      {
        case rR240:     return "Channel 0 Data Register";
        case rR241:     return "Channel 1 Data Register";
        case rR242:     return "Channel 2 Data Register";
        case rR243:     return "Channel 3 Data Register";
        case rR244:     return "Channel 4 Data Register";
        case rR245:     return "Channel 5 Data Register";
        case rR246:     return "Channel 6 Data Register";
        case rR247:     return "Channel 7 Data Register";
        case rR248:     return "Channel 6 Lower Threshold Register";
        case rR249:     return "Channel 6 Lower Threshold Register";
        case rR250:     return "Channel 7 Upper Threshold Register";
        case rR251:     return "Channel 7 Upper Threshold Register";
        case rR252:     return "Compare Result Register";
        case rR253:     return "Control Logic Register";
        case rR254:     return "Interrupt Control Register";
        case rR255:     return "Interrupt Vector Register";
      }
      break;
  }
  return NULL;
}

static const char *gr_cmt = NULL;

//--------------------------------------------------------------------------
// Output a register
static void out_reg(ushort reg)
{
  out_register(ph.regNames[reg]);
  const char *cmt = get_general_register_description(reg);
  if ( cmt != NULL && !has_cmt(uFlag) )
    gr_cmt = cmt;
}

//--------------------------------------------------------------------------
// Output an operand as a register
static void out_reg(const op_t &op)
{
  out_reg(op.reg);
}

//--------------------------------------------------------------------------
// Output an operand as an immediate value
static void out_imm(op_t &op, bool no_shift = false)
{
  if ( !is_imm_no_shift(op) && !no_shift )
    out_symbol('#');
  OutValue(op, OOFW_IMM);
}

//--------------------------------------------------------------------------
// Output an operand as an address
inline void out_addr(const op_t &op, bool find_label = true)
{
  if ( !find_label || !out_name_expr(op, toEA(cmd.cs, op.addr), op.addr) )
    OutValue(op, OOF_ADDR | OOFS_NOSIGN);
}

//--------------------------------------------------------------------------
// Generate disassembly header
void idaapi header(void)
{
  gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}

//--------------------------------------------------------------------------
// Generate disassembly footer
void idaapi footer(void)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  if ( ash.end != NULL )
  {
    MakeNull();
    char *p = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
    qstring name;
    if ( get_colored_name(&name, inf.beginEA) > 0 )
    {
      APPCHAR(p, end, ' ');
      APPEND(p, end, name.begin());
    }
    MakeLine(buf, inf.indent);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}

#define BEG_TAG(x)     if ( is_ind(x)) out_symbol('(' )
#define END_TAG(x)     if ( is_ind(x)) out_symbol(')' )

//--------------------------------------------------------------------------
// Output an operand
bool idaapi outop(op_t &op)
{
  switch ( op.type )
  {
    // Data / Code memory address
    case o_near:
    case o_mem:
      BEG_TAG(op);
      out_addr(op);
      END_TAG(op);
      break;

    // Immediate value
    case o_imm:
      BEG_TAG(op);
      {
        const ioport_t *port = find_sym(op.value);
        // this immediate is represented in the .cfg file
        if ( port != NULL ) // otherwise, simply print the value
          out_line(port->name, COLOR_IMPNAME);
        else // otherwise, simply print the value
          out_imm(op);
      }
      END_TAG(op);
      break;

    // Displacement
    case o_displ:
      out_addr(op, false);
      out_symbol('(');
      out_reg(op);
      out_symbol(')');
      break;

    // Register
    case o_reg:
      BEG_TAG(op);
      out_reg(op);
      END_TAG(op);
      if ( is_reg_with_bit(op) )
      {
        out_symbol('.');
        if ( is_bit_compl(op) )
          out_symbol('!');
        out_imm(op, true);
      }
      break;

    // Phrase
    case o_phrase:
      switch ( op.specflag2 )
      {
        case fPI:   // post increment
          out_symbol('(');
          out_reg(op);
          out_symbol(')');
          out_symbol('+');
          break;

        case fPD:   // pre decrement
          out_symbol('-');
          out_symbol('(');
          out_reg(op);
          out_symbol(')');
          break;

        case fDISP: // displacement
          out_reg(op);
          out_symbol('(');
          {
            ushort reg = op.specflag2 << 8;
            reg |= op.specflag3;
            out_reg(reg);
          }
          out_symbol(')');
          break;

        default:
          INTERR(10077);
      }
      break;

    // No operand
    case o_void:
      break;

    default:
      INTERR(10078);
  }
  return 1;
}

//--------------------------------------------------------------------------
// Output an instruction
void idaapi out(void)
{
  // print insn mnemonic
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  char postfix[5];
  postfix[0] = '\0';

  if ( is_jmp_cc(cmd.itype) )
    qstrncpy(postfix, ConditionCodes[cmd.auxpref], sizeof(postfix));

  OutMnem(8, postfix);

  //
  // print insn operands
  //

  out_one_operand(0);        // output the first operand

  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
  }

  if ( cmd.Op3.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(2);
  }

  // output a character representation of the immediate values
  // embedded in the instruction as comments
  if ( isVoid(cmd.ea,uFlag,0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea,uFlag,2) ) OutImmChar(cmd.Op3);

  if ( gr_cmt != NULL )
  {
    OutChar(' ');
    out_line(ash.cmnt, COLOR_AUTOCMT);
    OutChar(' ');
    out_line(gr_cmt, COLOR_AUTOCMT);
    if ( ash.cmnt2 != NULL )
    {
      OutChar(' ');
      out_line(ash.cmnt2, COLOR_AUTOCMT);
    }
    gr_cmt = NULL;
  }

  term_output_buffer();                   // terminate the output string
  gl_comm = 1;                            // ask to attach a possible user-
                                          // defined comment to it
  MakeLine(buf);                          // pass the generated line to the
                                          // kernel
}

//--------------------------------------------------------------------------
// Generate a segment header
void idaapi gen_segm_header(ea_t ea)
{
  segment_t *Sarea = getseg(ea);

  char sname[MAXNAMELEN];
  get_segm_name(Sarea, sname, sizeof(sname));

  char *segname = sname;
  if ( *segname == '_' )
    segname++;

  if ( ash.uflag & UAS_ASW )
    printf_line(inf.indent, COLSTR("SEGMENT %s", SCOLOR_ASMDIR), segname);
  else
    printf_line(inf.indent, COLSTR(".section .%s", SCOLOR_ASMDIR), segname);

  ea_t orgbase = ea - get_segm_para(Sarea);

  if ( orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}
