
/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"

//----------------------------------------------------------------------
static void OutVarName(op_t & x)
{
  ea_t addr = x.addr;
  ea_t toea = toEA(codeSeg(addr, x.n), addr);

  if (out_name_expr(x, toea, addr))
  {
    return;
  }
  else
  {
    OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    // add a problem: no name
    QueueSet(Q_noName, cmd.ea);
  }
}

//----------------------------------------------------------------------
// output one operand
bool idaapi CR16_outop(op_t & x)
{
  int flags;
  switch (x.type)
  {
    case o_displ:
      //OutValue(x, OOF_ADDR|OOFS_IFSIGN|OOF_SIGNED|OOFW_32);
      OutValue(x, /*OOFS_NOSIGN | */ OOF_ADDR | OOF_SIGNED | OOFW_IMM);
      out_symbol('(');
      if (x.specflag1 & URR_PAIR)
      {
        out_register(ph.regNames[x.reg + 1]);
        out_symbol(',');
        out_register(ph.regNames[x.reg]);
      }
      else
      {
        out_register(ph.regNames[x.reg]);
      }
      out_symbol(')');
      break;

    case o_reg:
      if (x.specflag1 & URR_PAIR)
      {
        out_symbol('(');
        out_register(ph.regNames[x.reg + 1]);
        out_symbol(',');
        out_register(ph.regNames[x.reg]);
        out_symbol(')');
      }
      else
      {
        out_register(ph.regNames[x.reg]);
      }
      break;

    case o_imm:
      out_symbol('$');
      flags = /*OOFS_NOSIGN |  OOF_SIGNED  | */OOFW_IMM;
      switch ( cmd.itype )
      {
        case CR16_addb:
        case CR16_addw:
        case CR16_addub:
        case CR16_adduw:
        case CR16_addcb:
        case CR16_addcw:
        case CR16_ashub:
        case CR16_ashuw:
        case CR16_lshb:
        case CR16_lshw:
          flags |= OOF_SIGNED;
          break;
      }
      OutValue(x, flags);
      break;

    case o_near:
      OutVarName(x);
      break;

    case o_mem:
      OutVarName(x);
      break;

    case o_void:
      return 0;

    default:
      warning("out: %a: bad optype %d", cmd.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
// main output function
void idaapi CR16_out(void)
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf)); // setup the output pointer
  // print mnemonic
  OutMnem();

  // print first operand
  if (cmd.Op1.type != o_void)
    out_one_operand(0);

  // print second operand
  if (cmd.Op2.type != o_void)
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
  }

  // print immediates
  if (isVoid(cmd.ea, uFlag, 0))
    OutImmChar(cmd.Op1);
  if (isVoid(cmd.ea, uFlag, 1))
    OutImmChar(cmd.Op2);

  // terminate line
  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
// header of the listing
void idaapi CR16_header(void)
{
  gen_header(GH_PRINT_ALL_BUT_BYTESEX, device[0] ? device : NULL, deviceparams);
}

//--------------------------------------------------------------------------
// segment start
void idaapi CR16_segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  const char *SegType = (Sarea->type == SEG_CODE) ? "CSEG" :
    ((Sarea->type == SEG_DATA) ? "DSEG" : "RSEG");
  // print RSEG <NAME>
  char sn[MAXNAMELEN];

  get_segm_name(Sarea, sn, sizeof(sn));
  printf_line(-1, "%s %s ", SegType, sn);
  // if offset not zero, print it (ORG XXXX)
  if ( inf.s_org )
  {
    ea_t org = ea - get_segm_base(Sarea);

    if (org != 0)
    {
      char bufn[MAX_NUMBUF];
      btoa(bufn, sizeof(bufn), org);
      printf_line(-1, "%s %s", ash.origin, bufn);
    }
  }
}

//--------------------------------------------------------------------------
// end of listing
void idaapi CR16_footer(void)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);

  if (ash.end != NULL)
  {
    MakeNull();
    char *ptr = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);

    qstring name;
    if ( get_colored_name(&name, inf.beginEA) > 0 )
    {
      size_t i = strlen(ash.end);
      do
        APPCHAR(ptr, end, ' ');
      while ( ++i < 8 );
      APPEND(ptr, end, name.begin());
    }
    MakeLine(buf, inf.indent);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
void idaapi CR16_data(ea_t ea)
{
  //refinfo_t ri;

  /*
  // micro bug-fix
  if (get_refinfo(ea, 0, &ri))
  {
    if (ri.flags == REF_OFF16)
    {
      set_refinfo(ea, 0, REF_OFF32, ri.target, ri.base, ri.tdelta);
      msg("Exec OFF16 Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n", ea,
          ri.flags, ri.target, ri.base, ri.tdelta);
    }
  }*/

  gl_name = 1;
  intel_data(ea);
}
