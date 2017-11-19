
#include "m7700.hpp"

//--------------------------------------------------------------------------
inline static void outreg(const int n)
{
  out_register(ph.regNames[n]);
}

//--------------------------------------------------------------------------
static void outaddr(const op_t &op, const bool replace_with_label = true)
{
  bool ind = is_addr_ind(op);      // is operand indirect ?

  if ( ind )
    out_symbol('(');

  // if addressing mode is direct and the value of DR is unknown,
  // we have to print DR:x (where x is the "indexed" value)
  if ( is_addr_dr_rel(op) && get_segreg(cmd.ea, rDR) == BADSEL )
  {
    outreg(rDR);
    out_symbol(':');
    OutValue(op, OOF_ADDR | OOFS_NOSIGN);
  }
  // otherwise ...
  else if ( !replace_with_label
         || !out_name_expr(op, toEA(cmd.cs, op.addr), op.addr) )
  {
    if ( replace_with_label) out_tagon(COLOR_ERROR );
    OutValue(op, OOF_ADDR | OOFS_NOSIGN /*| OOFW_16*/);
    if ( replace_with_label) out_tagoff(COLOR_ERROR );
  }

  if ( ind )
    out_symbol(')');
}

//--------------------------------------------------------------------------
static void outdispl(const op_t &op)
{
  if ( is_displ_ind(op) )
  {
    out_symbol('(');
    outaddr(op, false);
    out_symbol(',');
    if ( !(ash.uflag & UAS_INDX_NOSPACE) )
      OutChar(' ');
    outreg(op.reg);
    out_symbol(')');
  }
  else if ( is_displ_ind_p1(op) )
  {
    out_symbol('(');
    outaddr(op, false);
    out_symbol(')');
    out_symbol(',');
    OutChar(' ');
    outreg(op.reg);
  }
  else
  {
    outaddr(op, false);
    out_symbol(',');
    OutChar(' ');
    outreg(op.reg);
  }
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_header(GH_PRINT_ALL_BUT_BYTESEX, NULL, device);
  if ( ash.uflag & UAS_DEVICE_DIR )
  {
    switch ( ptype )
    {
      case prc_m7700: printf_line(inf.indent, ".MCU M37700"); break;
      case prc_m7750: printf_line(inf.indent, ".MCU M37750"); break;
      default:        INTERR(10029);
    }
  }
}

//--------------------------------------------------------------------------
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
      if ( ash.uflag & UAS_END_WITHOUT_LABEL )
      {
        APPCHAR(p, end, ';');
        APPCHAR(p, end, ' ');
      }
      APPEND(p, end, name.begin());
    }
    MakeLine(buf, inf.indent);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
static bool bitmask2list(const op_t &op)
{
  static const char *const flags[] =
  {
    "N", "V", "m", "x", "D", "I", "Z", "C"
  };
  static const int regs[] =
  {
    rPS, rPG, rDT, rDR, rY, rX, rB, rA
  };

  enum { bitFLAGS, bitREGS } t;
  switch ( cmd.itype )
  {
    case m7700_psh:
    case m7700_pul:
      t = bitREGS;
      break;

    case m7700_sep:
    case m7700_clp:
      t = bitFLAGS;
      break;

    default:
      return false;
  }

  if ( op.value == 0 )
    return false;

  bool ok = false;
  for ( int tmp = (int)op.value, i = 1, j = 0; j < 8; i *= 2, j++ )
  {
    if ( ((tmp & i) >> j) != 1 )
      continue;

    if ( ok )
    {
      out_symbol(',');
      OutChar(' ');
    }

    switch ( t )
    {
      case bitFLAGS: out_register(flags[7 - j]); break;
      case bitREGS:  outreg(regs[7 - j]);        break;
    }
    ok = true;
  }
  return true;
}

//--------------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  switch ( x.type )
  {
    // register
    case o_reg:
      outreg(x.reg);
      break;

    // immediate
    case o_imm:
      {
        bool list_ok = false;

        if ( ash.uflag & UAS_BITMASK_LIST )
            list_ok = bitmask2list(x);

        if ( !list_ok )
        {
          if ( !(is_imm_without_sharp(x)) )
            out_symbol('#');
          OutValue(x, OOFW_IMM);
        }
      }
      break;

    // bit
    case o_bit:
      {
        const ioport_bit_t * port = NULL;

        if ( x.n == 0 && (cmd.Op2.type == o_near || cmd.Op2.type == o_mem) )
          port = find_bit(cmd.Op2.addr, (size_t)x.value);

        // this immediate is represented in the .cfg file
        if ( port != NULL && port->name != NULL )
        {
          // output the port name instead of the numeric value
          out_line(port->name, COLOR_IMPNAME);
        }
        // otherwise, simply print the value
        else
        {
          out_symbol('#');
          OutValue(x, OOFW_IMM);
        }
      }
      break;

    // data / code memory address
    case o_near:
    case o_mem:
      outaddr(x);
      break;

    // displ
    case o_displ:
      outdispl(x);
      break;

    // ignore void operands
    case o_void:
      break;

    default:
      INTERR(10030);
  }
  return 1;
}

//--------------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  //
  // print insn mnemonic
  //

  char postfix[2];
  postfix[0] = '\0';
  if ( is_insn_long_format() )
  {
    postfix[0] = 'l';
    postfix[1] = '\0';
  }
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

  term_output_buffer();                   // terminate the output string
  gl_comm = 1;                            // ask to attach a possible user-
                                          // defined comment to it
  MakeLine(buf);                          // pass the generated line to the
                                          // kernel
}

//--------------------------------------------------------------------------
// generate segment header
void idaapi gen_segm_header(ea_t ea)
{
  segment_t *Sarea = getseg(ea);

  char sname[MAXNAMELEN];
  get_segm_name(Sarea, sname, sizeof(sname));
  char *segname = sname;

  if ( ash.uflag & UAS_SEGM )
    printf_line(inf.indent, COLSTR("SEGMENT %s", SCOLOR_ASMDIR), segname);
  else
    printf_line(inf.indent, COLSTR(".SECTION %s", SCOLOR_ASMDIR), segname);

  ea_t orgbase = ea - get_segm_para(Sarea);
  if ( orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
inline bool show_assume_line(const segreg_area_t *sra, ea_t ea, int segreg)
{
  bool show = false;
  if ( sra->startEA == ea )
  {
    segreg_area_t prev_sra;
    if ( get_prev_srarea(&prev_sra, ea, segreg) )
      show = sra->val != prev_sra.val;
  }
  return show;
}

//--------------------------------------------------------------------------
void idaapi gen_assumes(ea_t ea)         // function to produce assume directives
{
  segment_t *seg = getseg(ea);
  if ( !inf.s_assume || seg == NULL )
    return;
  bool seg_started = (ea == seg->startEA);

  segreg_area_t sra;
  if ( get_srarea2(&sra, ea, rDR) )
  {
    if ( (seg_started && sra.val != BADSEL) || show_assume_line(&sra, ea, rDR) )
      printf_line(-1, COLSTR("%s DPR = %a", SCOLOR_REGCMT), ash.cmnt, sra.val);
  }

  if ( get_srarea2(&sra, ea, rfM) )
  {
    if ( seg_started || show_assume_line(&sra, ea, rfM) )
      printf_line(-1, COLSTR("%s m = %a", SCOLOR_REGCMT), ash.cmnt, sra.val);
  }

  if ( get_srarea2(&sra, ea, rfX) )
  {
    if ( seg_started || show_assume_line(&sra, ea, rfX) )
      printf_line(-1, COLSTR("%s x = %a", SCOLOR_REGCMT), ash.cmnt, sra.val);
  }
}
