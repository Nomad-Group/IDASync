/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

//----------------------------------------------------------------------
static void OutVarName(op_t &x)
{
  ea_t addr = x.addr;
  ea_t toea = toEA(codeSeg(addr,x.n), addr);
  if ( !out_name_expr(x,toea,addr) )
  {
    OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    // пометим проблему - нет имени
    QueueSet(Q_noName,cmd.ea);
  }
}

//----------------------------------------------------------------------
// вывод одного операнда
bool idaapi C39_outop(op_t &x)
{
  switch ( x.type )
  {
    // только регистр
    case o_reg:
      out_register(ph.regNames[x.reg]);
      break;

    // непосредственные данные (8 бит)
    case o_imm:
      out_symbol('#');
      refinfo_t ri;
      // micro bug-fix
      if ( get_refinfo(cmd.ea, x.n, &ri) )
      {
        if ( ri.flags == REF_OFF16 )
        {
          set_refinfo(cmd.ea, x.n,
                      REF_OFF32, ri.target, ri.base, ri.tdelta);
//          msg("Exec OFF16_Op Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",
//                cmd.ea,
//                ri.flags,ri.target,ri.base,ri.tdelta);
        }
      }
      OutValue(x, /*OOFS_NOSIGN | */ OOF_SIGNED | OOFW_IMM);
      break;

    // прямая ссылка на программу (реально - относительно PC)
    case o_near:
      OutVarName(x);
      break;

    // обращение к ячейке памяти
    case o_mem:
      if ( x.specflag1&URR_IND )
        out_symbol('(');
      OutValue(x, OOFS_NOSIGN |  OOFW_IMM);
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
void idaapi C39_out(void)
{
  char buf[MAXSTR];
   init_output_buffer(buf, sizeof(buf)); // setup the output pointer
  // выведем мнемонику
  OutMnem();

  // выведем первый операнд
  if ( cmd.Op1.type != o_void )
    out_one_operand(0 );

  // выведем второй операнд
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
    // выведем третий операнд
    if ( cmd.Op3.type != o_void )
    {
      out_symbol(',');
      OutChar(' ');
      out_one_operand(2);
    }
  }

  // выведем непосредственные данные, если они есть
  if ( isVoid(cmd.ea,uFlag,0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea,uFlag,2) ) OutImmChar(cmd.Op3);

  // завершим строку
  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
// заголовок текста листинго
void idaapi C39_header(void)
{
  gen_header(GH_PRINT_ALL_BUT_BYTESEX, device[0] ? device : NULL, deviceparams);
}

//--------------------------------------------------------------------------
// начало сегмента
void idaapi C39_segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      :                           "RSEG";
  // Выведем строку вида RSEG <NAME>
  char sn[MAXNAMELEN];
  get_segm_name(Sarea,sn,sizeof(sn));
  printf_line(-1,"%s %s ",SegType, sn);
  // если смещение не ноль - выведем и его (ORG XXXX)
  if ( inf.s_org )
  {
    ea_t org = ea - get_segm_base(Sarea);
    if( org != 0 )
    {
      char bufn[MAX_NUMBUF];
      btoa(bufn, sizeof(bufn), org);
      printf_line(-1, "%s %s", ash.origin, bufn);
    }
  }
}

//--------------------------------------------------------------------------
// конец текста
void idaapi C39_footer(void)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  if ( ash.end != NULL )
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
    MakeLine(buf,inf.indent);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
void idaapi C39_data(ea_t ea)
{
  refinfo_t ri;
  // micro bug-fix
  if ( get_refinfo(ea, 0, &ri) )
  {
    if ( ri.flags == REF_OFF16 )
    {
      set_refinfo(ea, 0,
                    REF_OFF32, ri.target, ri.base, ri.tdelta);
//      msg("Exec OFF16 Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",ea,
//                    ri.flags,ri.target,ri.base,ri.tdelta);
    }
  }
  gl_name = 1;
  // попробуем  вывести, как equ
  //  if ( out_equ(ea) ) return;
  // не получилось - выводим данными
  intel_data(ea);
}
