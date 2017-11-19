/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c3x.hpp"
#include <frame.hpp>
#include <srarea.hpp>
#include <struct.hpp>

#define SYM(x) COLSTR(x, SCOLOR_SYMBOL)
#define REG(x) COLSTR(x, SCOLOR_REG)
#define REGP(x) SYM("(") REG(x) SYM(")")

// o_phrase output format strings, indexed by phtype
static const char *const formats[0x1a] =
{
        SYM("*+")  REG("%s"),                                     //0     "*+arn(NN)"
        SYM("*-")  REG("%s"),                                     //1     "*-arn(NN)"
        SYM("*++") REG("%s"),                                     //2     "*++arn(NN)"
        SYM("*--") REG("%s"),                                     //3     "*--arn(NN)"
        SYM("*")   REG("%s") SYM("++"),                           //4     "*arn++(NN)"
        SYM("*")   REG("%s") SYM("--"),                           //5     "*arn--(NN)"
        SYM("*")   REG("%s") SYM("++"),                           //6     "*arn++(NN)%"
        SYM("*")   REG("%s") SYM("--"),                           //7     "*arn--(NN)%"
        SYM("*+")  REG("%s") REGP("ir0"),                         //8     "*+arn(ir0)"
        SYM("*-")  REG("%s") REGP("ir0"),                         //9     "*-arn(ir0)"
        SYM("*++") REG("%s") REGP("ir0"),                         //a     "*++arn(ir0)"
        SYM("*--") REG("%s") REGP("ir0"),                         //b     "*--arn(ir0)"
        SYM("*")   REG("%s") SYM("++") REGP("ir0"),               //c     "*arn++(ir0)"
        SYM("*")   REG("%s") SYM("--") REGP("ir0"),               //d     "*arn--(ir0)"
        SYM("*")   REG("%s") SYM("++") REGP("ir0") SYM("%%"),     //e     "*arn++(ir0)%"
        SYM("*")   REG("%s") SYM("--") REGP("ir0") SYM("%%"),     //f     "*arn--(ir0)%"
        SYM("*+")  REG("%s") REGP("ir1"),                         //10    "*+arn(ir1)"
        SYM("*-")  REG("%s") REGP("ir1"),                         //11    "*-arn(ir1)"
        SYM("*++") REG("%s") REGP("ir1"),                         //12    "*++arn(ir1)"
        SYM("*--") REG("%s") REGP("ir1"),                         //13    "*--arn(ir1)"
        SYM("*")   REG("%s") SYM("++") REGP("ir1"),               //14    "*arn++(ir1)"
        SYM("*")   REG("%s") SYM("--") REGP("ir1"),               //15    "*arn--(ir1)"
        SYM("*")   REG("%s") SYM("++") REGP("ir1") SYM("%%"),     //16    "*arn++(ir1)%"
        SYM("*")   REG("%s") SYM("--") REGP("ir1") SYM("%%"),     //17    "*arn--(ir1)%"
        SYM("*")   REG("%s"),                                     //18    "*arn"
        SYM("*")   REG("%s") SYM("++") REGP("ir0") SYM("B"),      //19    "*arn++(ir0)B"
};

//--------------------------------------------------------------------------
static const char * const cc_text[] =
{
        //Unconditional compares
        "u",    //Unconditional

        //Unsigned compares
        "lo",   //Lower than
        "ls",   //Lower than or same as
        "hi",   //Higher than
        "hs",   //Higher than or same as
        "e",    //Equal to
        "ne",   //Not equal to

        //Signed compares
        "lt",   //Less than
        "le",   //Less than or equal to
        "gt",   //Greater than
        "ge",   //Greater than or equal to

        //Unknown
        "?",    //Unknown

        //Compare to condition flags
        "nv",   //No overflow
        "v",    //Overflow
        "nuf",  //No underflow
        "uf",   //Underflow
        "nlv",  //No latched overflow
        "lv",   //Latched overflow
        "nluf", //No latched floating-point underflow
        "luf",  //Latched floating-point underflow
        "zuf"   //Zero or floating-point underflow
};

//----------------------------------------------------------------------
static void out_address(ea_t ea, op_t &x, bool at)
{
    char buf[MAXSTR];
    if ( get_name_expr(cmd.ea+x.offb, x.n, ea, ea, buf, sizeof(buf)) > 0 )
    {
      if ( at )
        out_symbol('@');
      OutLine(buf);
    }
    else
    {
      if ( at )
        out_symbol('@');
      out_tagon(COLOR_ERROR);
      OutValue(x, OOFW_IMM|OOF_ADDR|OOFW_16);
      out_snprintf(" (ea = %a)", ea);
      out_tagoff(COLOR_ERROR);
      QueueSet(Q_noName, cmd.ea);
    }

}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  ea_t ea;
  char buf[MAXSTR];

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_register(ph.regNames[x.reg]);
      break;

    case o_near:
      out_address( calc_code_mem(x), x, false);
      break;

    case o_imm:
      if ( cmd.itype != TMS320C3X_TRAPcond)
        out_symbol('#');

      if ( cmd.auxpref & ImmFltFlag )
      {
         int16 v = int16(x.value);
         out_real(&v, 2, buf, sizeof(buf));
         out_line(buf[0] == ' ' ? &buf[1] : buf, COLOR_NUMBER);
      }
      else
      {
         OutValue(x, OOFW_IMM);
      }
      break;

    case o_mem:
      ea = calc_data_mem(x);
      if ( ea != BADADDR )
      {
        out_address(ea, x, true);
      }
      else
      {
        out_tagon(COLOR_ERROR);
        OutValue(x, OOFW_IMM|OOF_ADDR|OOFW_16);
        out_tagoff(COLOR_ERROR);
      }
      break;

    case o_phrase: // Indirect addressing mode
      {
        if ( x.phrase < qnumber(formats) )
        {
          op_t y = x;
          bool outdisp = x.phrase < 8;
          bool printmod = x.phrase >= 6;
          if ( x.phrase == 0x18 )
          {
            // this is *arn phrase
            // check if we need to print the displacement
            flags_t F = uFlag;
            int n = x.n;
            if ( isOff(F, n) || isStkvar(F, n) || isEnum(F, n) || isStroff(F, n) )
            {
              outdisp = true;
              y.addr = 0;
              printmod = false;
              y.phrase = 0; // use '*+arn(NN)' syntax
            }
          }

          // print the base part
          const char *reg = ph.regNames[uchar(y.phtype)];
          nowarn_qsnprintf(buf, sizeof(buf), formats[uchar(y.phrase)], reg);
          out_colored_register_line(buf);

          // print the displacement
          if ( outdisp )
          {
            out_symbol('(');
            OutValue(y, OOFS_IFSIGN|OOF_ADDR|OOFW_32);
            out_symbol(')');
            if ( printmod )
              out_symbol('%'); // %: circular modify
          }
        }
        else
        {
          out_line("<bad indirect>", COLOR_ERROR);
        }
        break;
      }

    default:
      error("interr: out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  // output instruction mnemonics
  char postfix[8];
  postfix[0] = '\0';
  switch ( cmd.itype )
  {
    case TMS320C3X_LDFcond:
    case TMS320C3X_LDIcond:
    case TMS320C3X_Bcond:
    case TMS320C3X_DBcond:
    case TMS320C3X_CALLcond:
    case TMS320C3X_TRAPcond:
    case TMS320C3X_RETIcond:
    case TMS320C3X_RETScond:
                qstrncpy(postfix, cc_text[cmd.auxpref & 0x1f ], sizeof(postfix));
                if ( cmd.auxpref & DBrFlag ) // если переход отложенный
                        qstrncat(postfix, "d", sizeof(postfix));
                break;
  }

  OutMnem(8, postfix);


  // по кол-ву операндов бывают такие сочетания в командах:
  // 0, 1, 2, 3 для непараллельных
  // 2+2, 3+2, 3+3, для параллельных

  out_one_operand(0);   //два операнда можно выводить смело
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    out_one_operand(1);
  }

  gl_comm = 1;                  // generate comments at the next MakeLine();
  if ( cmd.itype2 )             // Is Parallel
  {
        if ( cmd.i2op > 2 ) // 3-й операнд принадлежит первой половине команды
        {
                out_symbol(',');
                out_one_operand(2);
        }
        term_output_buffer();
        MakeLine(buf);
        init_output_buffer(buf, sizeof(buf));

        char insn2[MAXSTR];
        qsnprintf(insn2, sizeof(insn2), "||%s", ph.instruc[uchar(cmd.itype2)].name);
        add_spaces(insn2, sizeof(insn2), 8);
        out_line(insn2, COLOR_INSN);


        if ( cmd.i2op == 2 ) // 3-й операнд принадлежит второй половине команды
        {
                out_one_operand(2);
                out_symbol(',');
        }

        if ( cmd.Op4.type != o_void )
        {
                out_one_operand(3);
        }

        if ( cmd.Op5.type != o_void )
        {
                out_symbol(',');
                out_one_operand(4);
        }

        if ( cmd.Op6.type != o_void )
        {
                out_symbol(',');
                out_one_operand(5);
        }
  }
  else
        if ( cmd.Op3.type != o_void )
        {
                out_symbol(',');
                out_one_operand(2);
        }

  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea, uFlag, 2) ) OutImmChar(cmd.Op3);

  term_output_buffer();
  MakeLine(buf);
}

//--------------------------------------------------------------------------
static void print_segment_register(int reg, sel_t value)
{
  if ( reg == ph.regDataSreg ) return;
  if ( value != BADADDR )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), value);
    gen_cmt_line("assume %s = %s", ph.regNames[reg], buf);
  }
  else
  {
    gen_cmt_line("drop %s", ph.regNames[reg]);
  }
}

//--------------------------------------------------------------------------
// function to produce assume directives
void idaapi assumes(ea_t ea)
{
  segment_t *seg = getseg(ea);
  if ( !inf.s_assume || seg == NULL )
    return;
  bool seg_started = (ea == seg->startEA);

  for ( int i = ph.regFirstSreg; i <= ph.regLastSreg; ++i )
  {
    if ( i == ph.regCodeSreg )
      continue;
    segreg_area_t sra;
    if ( !get_srarea2(&sra, ea, i) )
      continue;
    if ( seg_started || sra.startEA == ea )
    {
      sel_t now = get_segreg(ea, i);
      segreg_area_t prev;
      bool prev_exists = get_srarea2(&prev, ea-1, i);
      if ( seg_started || (prev_exists && get_segreg(prev.startEA, i) != now) )
        print_segment_register(i, now);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;

  char sclas[MAXNAMELEN];
  get_segm_class(Sarea, sclas, sizeof(sclas));

  if ( strcmp(sclas,"CODE") == 0 )
    printf_line(inf.indent, COLSTR(".text", SCOLOR_ASMDIR));
  else if ( strcmp(sclas,"DATA") == 0 )
    printf_line(inf.indent, COLSTR(".data", SCOLOR_ASMDIR));

  if ( Sarea->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Sarea->orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t)
{
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_header(GH_PRINT_ALL | GH_BYTESEX_HAS_HIGHBYTE, NULL, device);
  MakeNull();
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  printf_line(inf.indent,COLSTR("%s",SCOLOR_ASMDIR),ash.end);
}

//--------------------------------------------------------------------------
void idaapi gen_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v)
{
  char sign = ' ';
  if ( v < 0 )
  {
    sign = '-';
    v = -v;
  }

  qstring name = get_member_name2(mptr->id);

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  qsnprintf(buf, bufsize,
            COLSTR("%s",SCOLOR_KEYWORD)
            COLSTR("%c%s",SCOLOR_DNUM)
            COLSTR(",",SCOLOR_SYMBOL) " "
            COLSTR("%s",SCOLOR_LOCNAME),
            ash.a_equ,
            sign,
            vstr,
            name.c_str());
}
