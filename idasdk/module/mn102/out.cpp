/*
 *      Panasonic MN102 (PanaXSeries) processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "pan.hpp"

//----------------------------------------------------------------------
class out_mn102_t : public outctx_t
{
  out_mn102_t(void) : outctx_t(BADADDR) {} // not used
public:
  void OutVarName(const op_t &x);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_mn102_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_mn102_t)

//----------------------------------------------------------------------
void out_mn102_t::OutVarName(const op_t &x)
{
  ea_t toea = map_code_ea(insn, x);
  if ( !out_name_expr(x, toea, x.addr) )
  {
    out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
// �뢮� ������ ���࠭��

bool out_mn102_t::out_operand(const op_t & x)
{
  switch ( x.type )
  {
    // ��뫪� �� ������ � �ᯮ�짮������ ॣ���� (ॣ���஢)
    // (disp,Ri)
    case o_displ: // ���뢠��� ᪮��� ���� �ᥣ��
                  // ॣ���� ���������?
      out_symbol('(');
      out_value(x);
      out_symbol(',');
      out_register(ph.reg_names[x.reg]);
      out_symbol(')');
      break;

    // ॣ����
    case o_reg:
      if ( x.reg&0x80 )
        out_symbol('(');
      if ( x.reg&0x10 )
      {
        out_register(ph.reg_names[((x.reg>>5)&3)+rD0]);
        out_symbol(',');
      }
      out_register(ph.reg_names[x.reg&0x0F]);
      if ( x.reg&0x80 )
        out_symbol(')');
      break;

    // �����।�⢥��� �����
    case o_imm:
      refinfo_t ri;
      // micro bug-fix
      if ( get_refinfo(&ri, insn.ea, x.n) )
      {
        if ( ri.flags == REF_OFF16 )
          set_refinfo(insn.ea, x.n, REF_OFF32, ri.target, ri.base, ri.tdelta);
      }
      out_value(x, /*OOFS_NOSIGN | */ OOF_SIGNED | OOFW_IMM);
      break;

    // ��뫪� �� �ணࠬ��
    case o_near:
      OutVarName(x);
      break;

    // ��ﬠ� ��뫪� �� ������
    case o_mem:
      out_symbol('(');
      OutVarName(x);
      out_symbol(')');
      break;

    // ����몠 �� �뢮�����
    case o_void:
      return 0;

    // ��������� ���࠭�
    default:
      warning("out: %a: bad optype %d",insn.ea,x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
// �᭮���� �뢮����� ������

void out_mn102_t::out_insn(void)
{
  // �뢥��� ���������
  out_mnemonic();

  // �뢥��� ���� ���࠭�
  if ( insn.Op1.type != o_void )
    out_one_operand(0);

  // �뢥��� ��ன ���࠭�
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
    // �뢥��� ��⨩ ���࠭�
    if ( insn.Op3.type != o_void )
    {
      out_symbol(',');
      out_char(' ');
      out_one_operand(2);
    }
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
// ��������� ⥪�� ���⨭��
void idaapi mn102_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, device.c_str(), deviceparams.c_str());
}

//--------------------------------------------------------------------------
// ��砫� ᥣ����
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void idaapi mn102_segstart(outctx_t &ctx, segment_t *Sarea)
{
  ea_t ea = ctx.insn_ea;
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      :                           "RSEG";
  // �뢥��� ��ப� ���� RSEG <NAME>
  qstring sn;
  get_visible_segm_name(&sn, Sarea);
  ctx.gen_printf(-1, "%s %s ", SegType, sn.c_str());
  // �᫨ ᬥ饭�� �� ���� - �뢥��� � ��� (ORG XXXX)
  if ( (inf.outflags & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      char bufn[MAX_NUMBUF];
      btoa(bufn, sizeof(bufn), org);
      ctx.gen_printf(-1, "%s %s", ash.origin, bufn);
    }
  }
}

//--------------------------------------------------------------------------
// ����� ⥪��
void idaapi mn102_footer(outctx_t &ctx)
{
  if ( ash.end != NULL )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf.start_ea) > 0 )
    {
      size_t i = strlen(ash.end);
      do
        ctx.out_char(' ');
      while ( ++i < 8 );
      ctx.out_line(name.begin());
    }
    ctx.flush_outbuf(inf.indent);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
void idaapi mn102_data(outctx_t &ctx, bool analyze_only)
{
  ea_t ea = ctx.insn_ea;
  // micro bug-fix
  refinfo_t ri;
  if ( get_refinfo(&ri, ea, 0) && ri.flags == REF_OFF16 )
    set_refinfo(ea, 0, REF_OFF32, ri.target, ri.base, ri.tdelta);

  // ���஡㥬  �뢥��, ��� equ
  //  if ( out_equ(ea) ) return;
  // �� ����稫��� - �뢮��� ����묨
  ctx.out_data(analyze_only);
}
