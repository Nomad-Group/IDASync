/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

//----------------------------------------------------------------------
class out_C39_t : public outctx_t
{
  out_C39_t(void) : outctx_t(BADADDR) {} // not used
public:
  void OutVarName(const op_t &x);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_C39_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_C39_t)

//----------------------------------------------------------------------
void out_C39_t::OutVarName(const op_t &x)
{
  ea_t toea = map_code_ea(insn, x);
  if ( !out_name_expr(x, toea, x.addr) )
  {
    out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
// вывод одного операнда
bool out_C39_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    // только регистр
    case o_reg:
      out_register(ph.reg_names[x.reg]);
      break;

    // непосредственные данные (8 бит)
    case o_imm:
      out_symbol('#');
      refinfo_t ri;
      // micro bug-fix
      if ( get_refinfo(&ri, insn.ea, x.n) )
      {
        if ( ri.flags == REF_OFF16 )
        {
          set_refinfo(insn.ea, x.n,
                      REF_OFF32, ri.target, ri.base, ri.tdelta);
//          msg("Exec OFF16_Op Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",
//                insn.ea,
//                ri.flags,ri.target,ri.base,ri.tdelta);
        }
      }
      out_value(x, /*OOFS_NOSIGN | */ OOF_SIGNED | OOFW_IMM);
      break;

    // прямая ссылка на программу (реально - относительно PC)
    case o_near:
      OutVarName(x);
      break;

    // обращение к ячейке памяти
    case o_mem:
      if ( x.specflag1&URR_IND )
        out_symbol('(');
      out_value(x, OOFS_NOSIGN | OOFW_IMM);
      if ( x.specflag1&URR_IND )
        out_symbol(')');
      break;

    // пустыка не выводится
    case o_void:
      return 0;

    // неизвестный операнд
    default:
      INTERR(10133);
  }
  return 1;
}

//----------------------------------------------------------------------
// основная выводилка команд
void out_C39_t::out_insn(void)
{
  // выведем мнемонику
  out_mnemonic();

  // выведем первый операнд
  if ( insn.Op1.type != o_void )
    out_one_operand(0);

  // выведем второй операнд
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
    // выведем третий операнд
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
// заголовок текста листинго
void idaapi C39_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, device.c_str(), deviceparams.c_str());
}

//--------------------------------------------------------------------------
// начало сегмента
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void idaapi C39_segstart(outctx_t &ctx, segment_t *Sarea)
{
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      :                           "RSEG";
  // Выведем строку вида RSEG <NAME>
  qstring sn;
  get_visible_segm_name(&sn, Sarea);
  ctx.gen_printf(-1,"%s %s ",SegType, sn.c_str());
  // если смещение не ноль - выведем и его (ORG XXXX)
  if ( (inf.outflags & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ctx.insn_ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      char bufn[MAX_NUMBUF];
      btoa(bufn, sizeof(bufn), org);
      ctx.gen_printf(-1, "%s %s", ash.origin, bufn);
    }
  }
}

//--------------------------------------------------------------------------
// конец текста
void idaapi C39_footer(outctx_t &ctx)
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
void idaapi C39_data(outctx_t &ctx, bool analyze_only)
{
  ea_t ea = ctx.insn_ea;
  // micro bug-fix
  refinfo_t ri;
  if ( get_refinfo(&ri, ea, 0) && ri.flags == REF_OFF16 )
    set_refinfo(ea, 0, REF_OFF32, ri.target, ri.base, ri.tdelta);

  ctx.out_data(analyze_only);
}
