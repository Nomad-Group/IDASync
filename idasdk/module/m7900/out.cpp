/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "7900.hpp"

static const char *const BitNamesCPU[] = { "IPL", "N", "V", "m", "x", "D", "I", "Z", "C" };
static const char *const BitNamesPUL[] = { "PS", "0", "DT", "DP0", "Y", "X", "B", "A" };

//----------------------------------------------------------------------
inline void SetDP0Plus(op_t &x)
{
  OutValue(x, OOFW_IMM | OOFW_16);
}

//----------------------------------------------------------------------
static void GetNumPUL(uval_t data)
{
  int bitOut=0;
  for ( int i=0; i<8; i++ )
  {
    if( GETBIT(data, i) == 1)
    {
      if ( bitOut != 0 )
        out_symbol(',');
      out_register( BitNamesPUL[7-i] );
      if ( bitOut == 0 )
        bitOut++;
    }
  }
}

//----------------------------------------------------------------------
static void GetNumDPRn(uval_t data)
{
  switch ( data )
  {
    case 0x1:
      out_symbol('0');
      break;
    case 0x2:
      out_symbol('1');
      break;
    case 0x4:
      out_symbol('2');
      break;
    case 0x8:
      out_symbol('3');
      break;
    default:
      out_symbol('(');
      bool add_comma = false;
      for ( int i=0; i < 4; ++i )
      {
        if ( GETBIT(data, i) == 1 )
        {
          if ( add_comma )
            out_symbol(',');
          out_long(i, 10);
          add_comma = true;
        }
      }
      out_symbol(')');
      break;
  }
}

//----------------------------------------------------------------------
static void GetCLPFlags(uval_t data)
{
  int bitOut=0;
  for(int i=0; i<8;i++)
  {
    if( GETBIT(data, i) == 1)
    {
      if ( bitOut != 0)  out_symbol(',' );
      out_register( BitNamesCPU[8-i] );
      if ( bitOut == 0 ) bitOut++;
    }
  }
}

//----------------------------------------------------------------------
inline void OutReg(int rgnum)
{
  out_register(ph.regNames[rgnum]);
}

//----------------------------------------------------------------------
static int OutVarName(op_t &x)
{
  return out_name_expr(x, toEA(cmd.cs, x.addr), x.addr);
}

//----------------------------------------------------------------------
static int getNumDPR(uval_t iDPR )
{
  switch ( iDPR )
   {
     case 0x0: return 0;
     case 0x40: return 1;
     case 0x80: return 2;
     case 0xC0: return 3;
   }
  return 0;

}

//----------------------------------------------------------------------
static void OutDPRReg(ea_t &Addr, uval_t gDPReg)
{
  if ( gDPReg == 1 )
  {
    char szTemp[5];
    uval_t Data = Addr;
    Data &= 0xC0;
    qsnprintf(szTemp, sizeof(szTemp), "DP%d", getNumDPR( Data ) );
    out_register(szTemp);
    Addr &= 0xFF3F;
  }
  else
  {
    out_keyword("DP0");
  }
}

//----------------------------------------------------------------------
static sel_t GetValueDP(int DPR )
{
  if ( getDPReg == 1 )
  {
    switch ( DPR )
    {
      case 0x0: return getDPR0;
      case 0x40: return getDPR1;
      case 0x80: return getDPR2;
      case 0xC0: return getDPR3;
    }
  }
  return 0;
}

//----------------------------------------------------------------------
static void OutDPR( uint32 Data )
{
  char tmp[20];

  ea_t Val = Data;
  OutDPRReg( Val, getDPReg);
  out_symbol(':');
  qsnprintf(tmp, sizeof(tmp), "%a", Val+GetValueDP( Data&0xC0 ) );
  out_line(tmp, COLOR_NUMBER);
}

//----------------------------------------------------------------------
static void OutDT( uint32 Data )
{
  char tmp[20];

  out_register("DT");
  out_symbol('+');
  out_symbol(':');

  qsnprintf(tmp, sizeof(tmp), "%X", Data );
  out_line(tmp, COLOR_NUMBER);
}

//----------------------------------------------------------------------
static void OutIMM(uint32 Data )
{
  char tmp[20];

  out_symbol('#');
  qsnprintf(tmp, sizeof(tmp), "%x", Data);
  out_line(tmp, COLOR_NUMBER);
}

//----------------------------------------------------------------------
static void MOVRB()
{
  int i;
  uint32 Val1, Val2;
  uchar code = get_byte(cmd.ea+1);
  uchar nib  = (code >> 4) & 0xF;
  uchar count = code & 0x0F;

  switch ( nib )
  {
    case 0x0:
      for ( i=0; i<count; i++ )
      {
        Val1 = get_byte( cmd.ea+2+(i*2) );//imm
        Val2 = get_byte( cmd.ea+2+(i*2)+1 );//dd

        //DPRxx
        OutDPR( Val2 );
        out_symbol(',');
        //imm
        OutIMM( Val1 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x1:
      for ( i=0; i<count; i++ )
      {
        Val2 = get_word( cmd.ea+2+(i*3) );//mmll
        Val1 = get_byte( cmd.ea+2+(i*3)+2 );//dd

        //DPRxx
        OutDPR( Val1 );
        out_symbol(',');
        //DPR
        OutDT( Val2 );
        out_symbol(',');
        OutReg(rX);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x2:
      for ( i=0; i<count; i++ )
      {
        Val1 = get_byte( cmd.ea+2+(i*3) );//imm
        Val2 = get_word( cmd.ea+2+(i*3)+1 );//mmll

        //DPRxx
        OutDT( Val2 );
        out_symbol(',');
        //IMM
        OutIMM( Val1 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x4:
      for( i=0; i<count; i++ )
      {
        Val1 = get_byte( cmd.ea+2+(i*2) );//dd1
        Val2 = get_byte( cmd.ea+2+(i*2)+1 );//dd2

        //DPRxx
        OutDPR( Val2 );
        out_symbol(',');
        //DPRxx
        OutDPR( Val1 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x6:
      for( i=0; i<count; i++ )
      {
        Val1 = get_byte( cmd.ea+2+(i*3) );//imm
        Val2 = get_word( cmd.ea+2+(i*3)+1 );//mmll

        //DPRxx
        OutDT( Val2 );
        out_symbol(',');
        //DPR
        OutDPR( Val1 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x7:
      for( i=0; i<count; i++ )
      {
         Val2 = get_byte( cmd.ea+2+(i*3) );//mmll
         Val1 = get_word( cmd.ea+2+(i*3)+1 );//dd

         //DPRxx
         OutDT( Val1 );
         out_symbol(',');
         //DPR
         OutDPR( Val2 );
         out_symbol(',');
         OutReg(rX);

         if ( i != (count-1) )
           out_symbol(',');
      }
      break;

    case 0x8:
      for ( i=0; i<count; i++ )
      {
        Val2 = get_word( cmd.ea+2+(i*3) );//mmll
        Val1 = get_byte( cmd.ea+2+(i*3)+2 );//dd

        //DPRxx
        OutDPR( Val1 );
        out_symbol(',');
        //DT
        OutDT( Val2 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0xA:
      for ( i=0; i<count; i++ )
      {
        Val1 = get_word( cmd.ea+2+(i*4) );//imm
        Val2 = get_word( cmd.ea+2+(i*4)+2 );//mmll

        //DPRxx
        OutDT( Val2 );
        out_symbol(',');
        //DT
        OutDT( Val1 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;
  }
}

//----------------------------------------------------------------------
static void MOVR()
{
  int i;
  uint32 Val1, Val2;
  uchar code = get_byte(cmd.ea+1);
  uchar nib  = (code >> 4) & 0xF;
  uchar count = code & 0x0F;

  switch ( nib )
  {
    case 0x0:
      for(i=0; i<count; i++)
      {
        Val2 = get_word( cmd.ea+2+(i*3) );//mmll
        Val1 = get_byte( cmd.ea+2+(i*3)+2 );//dd

        //DPRxx
        OutDPR( Val1 );
        out_symbol(',');
        //DT
        OutDT( Val2 );
        out_symbol(',');
        OutReg(rX);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x1:
      for ( i=0; i<count; i++ )
      {
        if ( getFlag_M == 0 )
        {
          Val2 = get_word( cmd.ea+2+(i*3) );//imm
          Val1 = get_byte( cmd.ea+2+(i*3)+2 );//dd
        }
        else
        {
          Val2 = get_byte( cmd.ea+2+(i*2) );//imm
          Val1 = get_byte( cmd.ea+2+(i*2)+1 );//dd
        }

        //DPRxx
        OutDPR( Val1 );
        out_symbol(',');
        //imm
        OutIMM( Val2 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x3:
      for ( i=0; i<count; i++ )
      {
         if ( getFlag_M == 0 )
         {
           Val2 = get_word( cmd.ea+2+(i*4) );//imm
           Val1 = get_word( cmd.ea+2+(i*4)+2 );//llmm
         }
         else
         {
           Val2 = get_byte( cmd.ea+2+(i*3) );//imm
           Val1 = get_word( cmd.ea+2+(i*3)+1 );//llmm
         }

         //DPRxx
         OutDT( Val1 );
         out_symbol(',');
         //IMM
         OutIMM( Val2 );

         if ( i != (count-1) )
           out_symbol(',');
      }
      break;

    case 0x5:
      for ( i=0; i<count; i++ )
      {
        Val2 = get_byte( cmd.ea+2+(i*2) );//dd
        Val1 = get_byte( cmd.ea+2+(i*2)+1 );//dd

        //DPRxx
        OutDPR( Val1 );
        out_symbol(',');
        //DPR
        OutDPR( Val2 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x6:
      for ( i=0; i<count; i++ )
      {
        Val1 = get_byte( cmd.ea+2+(i*3) );//imm
        Val2 = get_word( cmd.ea+2+(i*3)+1 );//mmll

        //DPRxx
        OutDT( Val2 );
        out_symbol(',');
        //DPR
        OutDPR( Val1 );
        out_symbol(',');
        OutReg(rX);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x7:
      for ( i=0; i<count; i++ )
      {
        Val2 = get_byte( cmd.ea+2+(i*3) );//mmll
        Val1 = get_word( cmd.ea+2+(i*3)+1 );//dd

        //DPRxx
        OutDT( Val1 );
        out_symbol(',');
        //DPR
        OutDPR( Val2 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x9:
      for ( i=0; i<count; i++ )
      {
        Val2 = get_word( cmd.ea+2+(i*3) );//mmll
        Val1 = get_byte( cmd.ea+2+(i*3)+2 );//dd

        //DPRxx
        OutDPR( Val1 );
        out_symbol(',');
        //DPR
        OutDT( Val2 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0xB:
      for(i=0; i<count; i++)
      {
        Val2 = get_word( cmd.ea+2+(i*4) );//imm
        Val1 = get_word( cmd.ea+2+(i*4)+2 );//llmm

        //DT
        OutDT( Val1 );
        out_symbol(',');
        //DT
        OutDT( Val2 );

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;
  }
}

//----------------------------------------------------------------------
static void MOV(op_t &x)
{
  switch ( x.TypeOper )
  {
    case m7900_movrb: MOVRB(); break;
    case m7900_movr:  MOVR();  break;
    default:
     //msg("out: %a: bad prefix %d\n", cmd.ip, RAZOPER);
     break;
  }
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      OutReg(x.reg);
      break;

    case o_phrase:
      OutLine(ph.regNames[x.reg]);
      break;

    case o_ab:
      switch ( x.TypeOper )
      {
        case TAB_L_INDIRECTED_ABS:
          out_symbol('L');

        case TAB_INDIRECTED_ABS:
          out_symbol('(');
          if ( !OutVarName(x)  )
             OutValue(x, OOF_ADDR | OOFS_NOSIGN);
          out_symbol(')');
          break;

        case TAB_INDIRECTED_ABS_X:
          out_symbol('(');

          if ( !OutVarName(x) )
             OutValue(x, OOF_ADDR | OOFS_NOSIGN);

          out_symbol(',');
          OutReg(rX);
          out_symbol(')');
          break;

        case TAB_ABS_Y:
        case TAB_ABS_X:
        case TAB_ABS:
          out_register("DT");
          out_symbol(':');

          if ( !OutVarName(x)  )
             OutValue(x, OOF_ADDR | OOFS_NOSIGN | OOFW_32);
          break;

        case TAB_ABL_X:
        case TAB_ABL:
          out_register("LG");
          out_symbol(':');

          if ( !OutVarName(x)  )
             OutValue(x, OOF_ADDR | OOFS_NOSIGN | OOFW_32);
          break;
      }
      break;

    case o_sr:
      if ( x.TypeOper == TSP_INDEX_SP_Y )
        out_symbol('(');

      if ( x.xmode == IMM_32 )
         OutValue(x, OOFW_IMM | OOFW_32);
      else if ( x.xmode == IMM_16 )
         OutValue(x, OOFW_IMM | OOFW_16);
      else
         OutValue(x, OOFW_IMM);

      if ( x.TypeOper == TSP_INDEX_SP_Y )
      {
        out_symbol(',');
        OutReg(rPS);
        out_symbol(')');
      }
      break;

    case o_stk:
      // there are special cases
      switch ( cmd.itype )
      {
        case m7900_pei: SetDP0Plus(x); break;
        case m7900_psh:
        case m7900_pul: GetNumPUL( x.value ); break;

        default:
          out_symbol('#');
          OutValue(x, OOFW_IMM | OOFS_NOSIGN);
          break;
      }
      break;

    case o_imm:
      // there are special cases
      switch ( cmd.itype )
      {
        case m7900_sep://Set Processor status
        case m7900_clp://CLear Processor status
          GetCLPFlags(x.value);
          break;

        case m7900_lddn:
        case m7900_tdan:
        case m7900_phdn:
        case m7900_rtsdn:
        case m7900_pldn:
        case m7900_rtld:
        case m7900_phldn:
          GetNumDPRn(x.value);
          break;
        case m7900_bsc:
        case m7900_bss:
          OutValue(x, OOFW_IMM);
          break;

        default:
          out_symbol('#');
          OutValue(x, OOFW_IMM);
          break;
      }
      break;//case o_imm

    case o_mem:
       // output memory variable name (for example 'byte_98')
      if ( x.TypeOper == m7900_movr || x.TypeOper == m7900_movrb )
      {
         MOV(x);
         break;
      }

      switch ( x.TypeOper )
      {
        case TDIR_DIR_Y:
        case TDIR_DIR_X:
        case TDIR_DIR:
          OutDPRReg(x.addr, getDPReg );
          out_symbol(':');
          if ( !OutVarName(x)  )
             OutValue(x, OOF_ADDR |OOF_NUMBER| OOFS_NOSIGN);
          break;

        case TDIR_L_INDIRECT_DIR_Y:
        case TDIR_L_INDIRECT_DIR:
          out_symbol('L');

        case TDIR_INDIRECT_DIR_Y:
        case TDIR_INDIRECT_DIR:
          out_symbol('(');
          OutDPRReg(x.addr, getDPReg );
          out_symbol(':');
          if ( !OutVarName(x)  )
            OutValue(x, OOF_ADDR |OOF_NUMBER| OOFS_NOSIGN);
          out_symbol(')');
         break;

        case TDIR_INDIRECT_DIR_X:
          out_symbol('(');

          OutDPRReg(x.addr, getDPReg );
          out_symbol(':');
          if ( !OutVarName(x)  )
            OutValue(x, OOF_ADDR |OOF_NUMBER| OOFS_NOSIGN);

          out_symbol(',');
          OutReg( rX);
          out_symbol(')');
          break;
      }
      break;

    case o_near:
      {
        ea_t v = toEA(cmd.cs,x.addr);
        if ( !out_name_expr(x, v, x.addr) )
        {
          OutValue(x, OOF_ADDR | OOFS_NOSIGN );
          //QueueSet(Q_noName, cmd.ea);
        }
      }
      break;

    default:
      //warning("out: %a: bad optype %d", cmd.ip, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
static const char *GetPrefics( int Raz)
{
  switch ( Raz )
  {
    case INSN_PREF_B: return ".b";
    case INSN_PREF_W: return "";
    case INSN_PREF_D: return ".d";
    case INSN_PREF_U: return "";
    default:
      //msg("out: %a: bad prefix %d\n", cmd.ip, RAZOPER);
      break;
  }
  return "";
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf));       // setup the output pointer
  OutMnem(8, GetPrefics(RAZOPER));            // output instruction mnemonics

  out_one_operand(0);                   // output the first operand

  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');    // operand sep
    if ( (ash.uflag & UAS_NOSPA) == 0 )
      OutChar(' ');
    out_one_operand(1);
  }

  if ( cmd.Op3.type != o_void )
  {
    out_symbol(',');
    if ( (ash.uflag & UAS_NOSPA) == 0 )
      OutChar(' ');
    out_one_operand(2);
  }

  if ( cmd.Op4.type != o_void )
  {
    out_symbol(',');
    if ( (ash.uflag & UAS_NOSPA) == 0 )
      OutChar(' ');
    out_one_operand(3);
  }


  if ( cmd.Op5.type != o_void )
  {
    out_symbol(',');
    if ( (ash.uflag & UAS_NOSPA) == 0 )
      OutChar(' ');
    out_one_operand(4);
  }


  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea, uFlag, 2) ) OutImmChar(cmd.Op3);
  if ( isVoid(cmd.ea, uFlag, 3) ) OutImmChar(cmd.Op4);
  if ( isVoid(cmd.ea, uFlag, 4) ) OutImmChar(cmd.Op5);

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_header(GH_PRINT_ALL_BUT_BYTESEX, NULL, device);
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
      register size_t i = strlen(ash.end);
      do
        APPCHAR(p, end, ' ');
      while ( ++i < 8 );
      APPEND(p, end, name.begin());
    }
    MakeLine(buf, inf.indent);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}
