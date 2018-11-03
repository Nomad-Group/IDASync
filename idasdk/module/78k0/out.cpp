/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"

//----------------------------------------------------------------------
class out_N78K_t : public outctx_t
{
  out_N78K_t(void) : outctx_t(BADADDR) {} // not used
public:
  void OutReg(int rgnum) { out_register(ph.reg_names[rgnum]); }
  void OutVarName(const op_t &x);
  void OutVarNameVal(const op_t &x);

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_N78K_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_N78K_t)

//----------------------------------------------------------------------
void out_N78K_t::OutVarName(const op_t &x)
{
  ushort addr = ushort(x.addr);
  ea_t toea = map_code_ea(insn, addr, x.n);
  if ( !out_name_expr(x, toea, addr) )
    out_value(x, OOF_ADDR | OOFW_16);
}

//----------------------------------------------------------------------
void out_N78K_t::OutVarNameVal(const op_t &x)
{
  ushort addr = ushort(x.value);
  ea_t toea = map_code_ea(insn, addr, x.n);
  if ( !out_name_expr(x, toea, addr) )
    out_value(x, OOFW_16);
}

//----------------------------------------------------------------------
// вывод одного операнда
bool out_N78K_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return 0;
    case o_reg:
      if ( x.FormOut & FORM_OUT_SKOBA )
        out_symbol('[');
      OutReg(x.reg);
      if ( x.FormOut & FORM_OUT_PLUS )
        out_symbol('+');
      if ( x.FormOut & FORM_OUT_DISP )
      {
        if ( is_off(F, x.n) )
          OutVarNameVal(x);
        else
          out_value(x, OOFW_IMM);
      }
      if ( x.FormOut & FORM_OUT_REG )
        out_keyword(ph.reg_names[uchar(x.SecondReg)]);
      if ( x.FormOut & FORM_OUT_SKOBA )
        out_symbol(']');
      break;

    case o_bit:
      switch ( x.FormOut )
      {
        case FORM_OUT_S_ADDR:
        case FORM_OUT_SFR:
          OutVarName(x);
          out_symbol('.');
          if ( !nec_find_ioport_bit(*this, (int)x.addr, (int)x.value) )
            out_value(x, OOFW_IMM);
          break;

        case FORM_OUT_A:
          out_line("A.");
          out_value(x, OOFW_IMM);
          break;

        case FORM_OUT_PSW:
          out_line("PSW.");
          switch ( x.value )
          {
            case 0: out_line("CY");         break;
            case 1: out_line("ISP");        break;
            case 3: out_line("RBS0");       break;
            case 4: out_line("AC");         break;
            case 5: out_line("RBS1");       break;
            case 6: out_line("Z");          break;
            case 7: out_line("IE");         break;
            default:out_value(x, OOFW_IMM); break;
          }
          break;

        case FORM_OUT_HL:
          out_symbol('[');
          OutReg(rHL);
          out_symbol(']');
          out_symbol('.');
          if ( is_off(F, x.n) )
            OutVarNameVal(x);
          else
            out_value(x, OOFW_IMM);
          break;

      }
      break;

    case o_imm:
      out_symbol('#');
      if ( is_off(F, x.n) )
        OutVarNameVal(x);
      else
        out_value(x, OOFW_IMM);
      break;

    case o_mem:
      //выводит имя переменной из памяти(например byte_98)
      if ( x.FormOut & FORM_OUT_VSK )
        out_symbol('!');
      if ( x.FormOut & FORM_OUT_SKOBA )
        out_symbol('[');
      //Вывод имени переменной
      OutVarName(x);
      if ( x.FormOut & FORM_OUT_SKOBA )
        out_symbol(']');
      break;

    case o_near:
      if ( x.FormOut & FORM_OUT_VSK )
        out_symbol('!');
      if ( x.FormOut & FORM_OUT_SKOBA )
        out_symbol('[');
      {
        ea_t adr = map_code_ea(insn, x);
        if ( !out_name_expr(x, adr, x.addr) )
        {
          out_value(x, OOF_ADDR | OOF_NUMBER | OOFW_16);
          remember_problem(PR_NONAME, insn.ea);
        }
      }
      if ( x.FormOut & FORM_OUT_SKOBA )
        out_symbol(']');
      break;

    // неизвестный операнд
    default:
      INTERR(10130);
  }
  return 1;
}

//----------------------------------------------------------------------
// основная выводилка команд
void out_N78K_t::out_insn(void)
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
  }
  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void idaapi N78K_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, device.c_str(), deviceparams.c_str());
}

//--------------------------------------------------------------------------
// начало сегмента
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void idaapi N78K_segstart(outctx_t &ctx, segment_t *Sarea)
{
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      : "RSEG";
  // Выведем строку вида RSEG <NAME>
  qstring sn;
  get_visible_segm_name(&sn, Sarea);
  ctx.gen_printf(-1,"%s %s ", SegType, sn.c_str());
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
void idaapi N78K_footer(outctx_t &ctx)
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

