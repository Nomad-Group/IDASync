/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"

//----------------------------------------------------------------------
static inline void OutReg(int rgnum)
{
  out_register(ph.regNames[rgnum]);
}

//----------------------------------------------------------------------
static void OutVarName(op_t &x)
{
  ushort addr = ushort(x.addr);
  ea_t toea = toEA(codeSeg(addr,x.n), addr);
  if ( !out_name_expr(x,toea,addr) )
    OutValue(x, OOF_ADDR | OOFW_16);
}

//----------------------------------------------------------------------
static void OutVarNameVal(op_t &x)
{
  ushort addr = ushort(x.value);
  ea_t toea = toEA(codeSeg(addr,x.n), addr);
  if ( !out_name_expr(x,toea,addr) )
    OutValue(x, OOFW_16);
}

//----------------------------------------------------------------------
// вывод одного операнда
bool idaapi N78K_outop(op_t &x)
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
        if ( isOff(uFlag, x.n) )
          OutVarNameVal(x);
        else
          OutValue(x, OOFW_IMM);
      }
      if ( x.FormOut & FORM_OUT_REG )
        out_keyword( ph.regNames[uchar(x.SecondReg)] );
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
          if ( !nec_find_ioport_bit((int)x.addr, (int)x.value) )
            OutValue(x, OOFW_IMM);
          break;

        case FORM_OUT_A:
          OutLine("A.");
          OutValue(x, OOFW_IMM);
          break;

        case FORM_OUT_PSW:
          OutLine("PSW.");
          switch ( x.value )
          {
            case 0: OutLine("CY");         break;
            case 1: OutLine("ISP");        break;
            case 3: OutLine("RBS0");       break;
            case 4: OutLine("AC");         break;
            case 5: OutLine("RBS1");       break;
            case 6: OutLine("Z");          break;
            case 7: OutLine("IE");         break;
            default:OutValue(x, OOFW_IMM); break;
          }
          break;

        case FORM_OUT_HL:
          out_symbol('[');
          OutReg(rHL);
          out_symbol(']');
          out_symbol('.');
          if ( isOff(uFlag, x.n) )
            OutVarNameVal(x);
          else
            OutValue(x, OOFW_IMM);
          break;

      }
      break;

    case o_imm:
      out_symbol('#');
      if ( isOff(uFlag, x.n) )
        OutVarNameVal(x);
      else
        OutValue(x, OOFW_IMM);
      break;

    case o_mem:
      //выводит имя переменной из памяти(например byte_98)
      if ( x.FormOut & FORM_OUT_VSK )
        out_symbol('!' );
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
        ea_t adr = toEA(codeSeg(x.addr, x.n), x.addr);
        if( !out_name_expr(x, adr, x.addr) )
        {
          OutValue(x, OOF_ADDR | OOF_NUMBER | OOFW_16);
          QueueSet(Q_noName, cmd.ea);
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
void idaapi N78K_out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf)); // setup the output pointer
  // выведем мнемонику
  OutMnem();

  // выведем первый операнд
  if ( cmd.Op1.type!=o_void )
    out_one_operand(0);
  // выведем второй операнд
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
  }
  // выведем непосредственные данные, если они есть
  if ( isVoid(cmd.ea, uFlag, 0) )
    OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) )
    OutImmChar(cmd.Op2);
  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi N78K_header(void)
{
  gen_header(GH_PRINT_ALL_BUT_BYTESEX, device[0] ? device : NULL, deviceparams);
}

//--------------------------------------------------------------------------
// начало сегмента
void idaapi N78K_segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      : "RSEG";
  // Выведем строку вида RSEG <NAME>
  char sn[MAXNAMELEN];
  get_segm_name(Sarea, sn, sizeof(sn));
  printf_line(-1,"%s %s ", SegType, sn);
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
void idaapi N78K_footer(void)
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
void idaapi N78K_data(ea_t ea)
{
  gl_name = 1;
  intel_data(ea);
}
