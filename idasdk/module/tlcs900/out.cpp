/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"

// �ࠧ�
static const char *const phrases[] =
{
  // �㫥���
  "",
  // �᫮���
  "F", "LT", "LE", "ULE", "PE", "MI", "Z", "C" ,
  "(T)", "GE", "GT", "UGT", "PO", "PL", "NZ", "NC",
  // ᯥ�ॣ����
  "F","F'",
  // ��祥
  "SR","PC"
};


// ��ਠ��� �������� ॣ���஢
static const uchar reg_byte[8]=
{
    rW,   rA,   rB,   rC,   rD,   rE,   rH,   rL
};
static const uchar reg_word[8]=
{
   rWA,  rBC,  rDE,  rHL,  rIX,  rIY,  rIZ,  rSP
};
static const uchar reg_long[8]=
{
  rXWA, rXBC, rXDE, rXHL, rXIX, rXIY, rXIZ, rXSP
};
static const uchar reg_ib[8]=
{
  rIXL, rIXH, rIYL, rIYH, rIZL, rIZH, rSPL, rSPH
};

//----------------------------------------------------------------------
// �뢥�� �������� ॣ����
static inline void OutReg(size_t rgnum, uchar size)
{
  ushort reg_name=0;      // ��� �᭮���� �ࠧ� ॣ����
  if ( size!=dt_dword )
  {
    // �᫨ 32 - ��� ��䨪ᮢ!
    if ( rgnum&2 ) // ��䨪� Q
      out_symbol('Q');
    else if ( rgnum<0xD0 ) //�.�. �㦥� R ?
      out_symbol('R');
  }
  // �뤠��� ᠬ� �������� ॣ����
  switch ( size )
  {
    case dt_byte:
      if ( (rgnum&0xF0) != 0xF0 )
        // ����� ॣ�����
        reg_name=reg_byte[((1-rgnum)&1)|((rgnum>>1)&6)];
      else
        // ���⮢� I*- ॣ�����
        reg_name=reg_ib[(rgnum&1)|((rgnum>>1)&6)];
      break;
    case dt_word:
      if ( (rgnum&0xF0) != 0xF0 )
        // �� �᭮��� ᫮��� ॣ�����
        reg_name=reg_word[(rgnum>>2)&3];
      else
        // ���訥 ॣ�����
        reg_name=reg_word[((rgnum>>2)&3)+4];
      break;
    case dt_dword:
      if ( (rgnum&0xF0)!=0xF0 )
        // �� �᭮��� ᫮��� ॣ�����
        reg_name=reg_long[(rgnum>>2)&3];
      else
        // ���訥 ॣ�����
        reg_name=reg_long[((rgnum>>2)&3)+4];
      break;

    case 255: // ᯥ�ॣ�����
      reg_name=ushort(rgnum);
      break;
  }
  if ( reg_name >= ph.regsNum )
  {
    out_symbol('?');
    msg("Bad Register Ref=%x, size=%x\n",(int)reg_name,(int)size);
  }
  else
  {
    out_register(ph.regNames[reg_name]);
  }
  // �뤠��� ����䨪� ॣ����
  if ( (rgnum&0xF0) == 0xD0 )
    out_symbol('\'');   // �������
  else if ( rgnum < 0xD0 ) // ��� �������� �����
    out_symbol('0'+((rgnum>>4)&0xF));
}

//----------------------------------------------------------------------
// ������� ��� ��⪨
static void OutVarName(op_t &x)
{
  ea_t addr = x.addr;
  ea_t toea = toEA(codeSeg(addr,x.n), addr);
  if ( out_name_expr(x,toea,addr) )
    return;
  OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
  // ����⨬ �஡���� - ��� �����
  QueueSet(Q_noName,cmd.ea);
}

//----------------------------------------------------------------------
// �뢮� ������ ���࠭��
bool idaapi T900_outop(op_t &x)
{
  switch ( x.type )
  {
    // ⮫쪮 ॣ����,  ��� ᯥ�䨪�, �� � ������
    case o_reg:
      OutReg((size_t)x.value,x.dtyp);
      break;

    // �ࠧ�
    case o_phrase:
      OutLine(phrases[x.phrase]);
      break;

    // �����।�⢥��� �����
    case o_imm:
ImmOut:
      refinfo_t ri;
      // micro bug-fix
      if ( get_refinfo(cmd.ea, x.n, &ri) )
      {
        if ( ri.flags==REF_OFF16 )
          set_refinfo(cmd.ea, x.n, REF_OFF32, ri.target, ri.base, ri.tdelta);
//        msg("Exec OFF16_Op Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",
//            cmd.ea, ri.flags,ri.target,ri.base,uval_t(ri.tdelta));
      }
      OutValue(x, OOFS_NOSIGN | OOFW_IMM);
      break;

    // ��ﬠ� ��뫪� �� ������ ��� �ணࠬ��
    case o_mem:
    case o_near:
      if ( x.specflag1&URB_LDA2 && isDefArg1(getFlags(cmd.ea)) )
        goto ImmOut;
      if ( !(x.specflag1&URB_LDA) )
        out_symbol('(');
      // ����稬 ���, �᫨ ��� ����
      OutVarName(x);
      if ( !(x.specflag1&URB_LDA) )
        out_symbol(')');
      break;

    // ��뫪� �� ������ � �ᯮ�짮������ ॣ���� (ॣ���஢)
    case o_displ: // ���뢠��� ᪮��� ���� �ᥣ��
      if ( !(x.specflag1&URB_LDA) )
        out_symbol('(');
      // ॣ���� ���������?
      if ( x.reg != rNULLReg )
      {
        // �᫨ �� ���६��� - ���⠢�� �����
        if ( x.specflag2 & URB_DECR )
          out_symbol('-');
        // �뢥��� �᭮���� ॣ����
        OutReg(x.reg, 2);        // ࠧ��� �ᥣ�� 32 ���
        // ���� ���६��� ?
        if ( x.specflag2 & URB_DCMASK )
        {
          if ( (x.specflag2&URB_DECR) == 0 )
            out_symbol('+');
          out_symbol(':');
          out_symbol('0'+(x.specflag2&7));
        }
        // ��ࠡ�⪠ �������� ���६�⮢
        if ( x.specflag2 & URB_UDEC )
          out_symbol('-');
        if ( x.specflag2 & URB_UINC )
          out_symbol('+');
        // ᬥ饭�� ���� ?
        if ( x.offb!=0 )
        {
          out_symbol('+');
          // �᫨ ᬥ饭�� - �뢥��� ᬥ饭���
          if ( isOff(uFlag,x.n) )
            OutVarName(x);
          else
            OutValue(x,OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
        }
        // �������⥫�� ॣ���� ����?
        if ( x.specval_shorts.low != rNULLReg )
        {
          out_symbol('+');
          OutReg(x.specval_shorts.low, x.specflag1&URB_WORD ? dt_word : dt_byte);
        }
      }
      // ����뢠��� ᪮��� ⮦� ���� �ᥣ��
      if ( !(x.specflag1&URB_LDA) )
        out_symbol(')');
      break;

    case o_void: // ����몠 �� �뢮�����
      return 0;

    default:     // ��������� ���࠭�
      warning("out: %a: bad optype %d", cmd.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
// �᭮���� �뢮����� ������
void idaapi T900_out(void)
{
  char buf[MAXSTR];
#if IDP_INTERFACE_VERSION > 37
   init_output_buffer(buf, sizeof(buf)); // setup the output pointer
#else
   u_line = buf;
#endif
  // �뢥��� ���������
  OutMnem();

  // �뢥��� ���� ���࠭�
  if ( cmd.Op1.type!=o_void)out_one_operand(0 );

  // �뢥��� ��ன ���࠭�
  if ( cmd.Op2.type != o_void ){
        out_symbol(',');
        OutChar(' ');
        out_one_operand(1);
  }

  // �뢥��� �����।�⢥��� �����, �᫨ ��� ����
  if ( isVoid(cmd.ea,uFlag,0) )
    OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) )
    OutImmChar(cmd.Op2);

  // �����訬 ��ப�
#if IDP_INTERFACE_VERSION > 37
  term_output_buffer();
#else
  *u_line = '\0';
#endif
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
// ��������� ⥪�� ���⨭��
void idaapi T900_header(void)
{
  gen_header(GH_PRINT_ALL_BUT_BYTESEX
#if IDP_INTERFACE_VERSION > 37
             , device[0] ? device : NULL
             , deviceparams
#endif
             );
}

//--------------------------------------------------------------------------
// ��砫� ᥣ����
void idaapi T900_segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  const char *SegType = Sarea->type==SEG_CODE ? "CSEG"
                      : Sarea->type==SEG_DATA ? "DSEG"
                      :                         "RSEG";
  // �뢥��� ��ப� ���� RSEG <NAME>
  char sn[MAXNAMELEN];
  get_segm_name(Sarea,sn,sizeof(sn));
  printf_line(-1,"%s %s ",SegType, sn);
  // �᫨ ᬥ饭�� �� ���� - �뢥��� � ��� (ORG XXXX)
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
// ����� ⥪��
void idaapi T900_footer(void)
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
    MakeLine(buf, inf.indent);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
void idaapi T900_data(ea_t ea)
{
  refinfo_t ri;
  // micro bug-fix
  if ( get_refinfo(ea, 0, &ri) )
  {
    if ( ri.flags == REF_OFF16 )
    {
      set_refinfo(ea, 0, REF_OFF32, ri.target, ri.base, ri.tdelta);
//      msg("Exec OFF16 Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",
//          ea, ri.flags, ri.target, ri.base, uval_t(ri.tdelta));
    }
  }
  gl_name = 1;
  intel_data(ea);
}
