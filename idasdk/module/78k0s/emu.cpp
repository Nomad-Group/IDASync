/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "78k_0s.hpp"

static bool flow;
//------------------------------------------------------------------------
// �������஢���� � �����(㪠��� �����) �� 㪠������� ⨯�,
// �������� ��� ��७�� ��� ⥪�饩 ������樨
void DataSet(op_t &x, ea_t EA, int isload)
{
  // �������஢���� � �����(㪠��� �����) �� 㪠������� ⨯�
  ua_dodata2(x.offb, EA, x.dtyp);
  //�������� ��� ��७�� ��� ⥪�饩 ������樨
  ua_add_dref(x.offb, EA, isload ? dr_R : dr_W);
}
//----------------------------------------------------------------------
static void TouchArg(op_t &x,int isAlt,int isload)
  {
  switch ( x.type )
  {
    case o_phrase:
      //������塞 � ᯨ᮪ �訡��(�뢮��� ᮮ�饭��)
      //�訡�� � ����� ��� �� ��稫���
      //QueueSet(Q_jumps, cmd.ea);
    case o_void:
    case o_reg:
      break;

    case o_imm:
      //��⠭����� ��� ������� ���� �ਧ��� immedia
      doImmd(cmd.ea);
      //������� 䫠� ��� 㪠������� ��������� �����
      if ( !isAlt )
      {
        uint32 offb;
        ushort addr = ushort(x.addr);
        if ( x.type == o_displ  )
        {
          addr += (ushort)cmd.ip;
          addr += cmd.size;
          //������� ������� �����
          offb = (uint32)toEA(codeSeg(addr,x.n), 0);
          DataSet(x, offb+addr, isload);
        }
        else if ( op_adds_xrefs(uFlag, x.n) )
        {
REREF:
          ea_t target = ua_add_off_drefs(x, dr_O);
          if ( x.type == o_displ && target != BADADDR )
            //�८�ࠧ����� ����� �� 㪠������� ��������� ������ � 㪠����� ⨯
            ua_dodata2(x.offb, target, x.dtyp);
        }
        else if ( x.type == o_displ && !x.reg && !isDefArg(uFlag, x.n )
               && set_offset(cmd.ea, x.n, toEA(cmd.cs,0)) )
        {
          goto REREF;
        }
      }
      break;

    case o_bit:
    case o_mem:
      // �������஢���� � �����(㪠��� �����) �� 㪠������� ⨯�,
      //�������� ��� ��७�� ��� ⥪�饩 ������樨
      DataSet(x, toEA(codeSeg(x.addr,x.n), x.addr), isload);
      break;

    case o_near:
      {
      //������� ������� �����
      ea_t ea = toEA(cmd.cs, x.addr);
      //�஢���� ���� �� ���祭�� �� 㪠������� ��������� ������ - ������樥�
      int iscall = InstrIsSet(cmd.itype, CF_CALL);
      //�������� ��� ��७�� ��� ⥪�饩 ������樨
      ua_add_cref(x.offb, ea, iscall ? fl_CN : fl_JN);
      if ( iscall )  flow = func_does_return(ea);
      } break;

    default:
      warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
      break;
  }
}
//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  flow = (Feature & CF_STOP) == 0;

  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);
  int flag3 = is_forced_operand(cmd.ea, 2);

  if ( Feature & CF_USE1 ) TouchArg(cmd.Op1, flag1, 1);
  if ( Feature & CF_USE2 ) TouchArg(cmd.Op2, flag2, 1);
  if ( Feature & CF_USE3 ) TouchArg(cmd.Op3, flag3, 1);
  if ( Feature & CF_JUMP ) QueueSet(Q_jumps, cmd.ea );
  if ( Feature & CF_CHG1 ) TouchArg(cmd.Op1, flag1, 0);
  if ( Feature & CF_CHG2 ) TouchArg(cmd.Op2, flag2, 0);
  if ( Feature & CF_CHG3 ) TouchArg(cmd.Op3, flag3, 0);

  if ( flow ) ua_add_cref(0, cmd.ea + cmd.size, fl_F);

  return 1;
}
//----------------------------------------------------------------------
