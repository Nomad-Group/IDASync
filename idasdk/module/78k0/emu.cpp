/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"

static bool flow;       // 䫠��� �⮯
//----------------------------------------------------------------------
// ���⠢�� �ᯮ�짮�����/��������� ���࠭���
static void handle_operand(const op_t &x,int isAlt,int isload, const insn_t &insn)
{
  ea_t ea = map_code_ea(insn, x.addr, x.n);
  ea_t ev = map_code_ea(insn, x.value, x.n);
  switch ( x.type )
  {
    // �� ���� �� �ᯮ������ !
    case o_void:
      break;

    case o_reg:
      if ( isAlt )
        break;
      if ( is_off(get_flags(insn.ea), x.n) )
        insn.add_dref(ev, x.n, dr_O);
      break;

    case o_imm:     // �����।�⢥��� �� ����� ��������
      if ( !isload )
        goto badTouch;
      // ���⠢�� 䫠��� �����।�⢥����� ���࠭�
      set_immd(insn.ea);
      // �᫨ �� ���஢�� � ����祭 ᬥ饭���
      if ( !isAlt && is_off(get_flags(insn.ea), x.n) )
        insn.add_dref(ev, x.offb, dr_O); // �� ᬥ饭�� !
      break;

    case o_mem:
      insn.create_op_data(ea, x);
      // �᫨ ��������� - ���⠢�� ��६�����
      insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      break;


    case o_near:// �� �맮� ? (��� ���室)
      if ( has_insn_feature(insn.itype, CF_CALL) )
      {
        // ���⠢�� ��뫪� �� ���
        insn.add_cref(ea, x.offb, fl_CN);
        flow = func_does_return(ea);
      }
      else
      {
        insn.add_cref(ea, x.offb, fl_JN);
      }
      break;

    case o_bit:
      switch ( x.FormOut )
      {
        case FORM_OUT_S_ADDR:
        case FORM_OUT_SFR:
          insn.create_op_data(ea, x);
          insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
          break;
      }
      break;
    // ��祥 - ᮮ�騬 �訡��
    default:
badTouch:
      warning("%a %s,%d: bad optype %d",
              insn.ea, insn.get_canon_mnem(),
              x.n, x.type);
      break;
  }
}


//----------------------------------------------------------------------
// ������

int idaapi N78K_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();
  // ����稬 ⨯� ���࠭���
  int flag1 = is_forced_operand(insn.ea, 0);
  int flag2 = is_forced_operand(insn.ea, 1);

  flow = (Feature & CF_STOP) == 0;

  // ����⨬ ��뫪� ���� ���࠭���
  if ( Feature & CF_USE1) handle_operand(insn.Op1, flag1, 1, insn);
  if ( Feature & CF_USE2) handle_operand(insn.Op2, flag2, 1, insn);
  // ���⠢�� ���室 � ��।�
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);
  // ���⠢�� ���������
  if ( Feature & CF_CHG1) handle_operand(insn.Op1, flag1, 0, insn);
  if ( Feature & CF_CHG2) handle_operand(insn.Op2, flag2, 0, insn);
  // �᫨ �� �⮯ - �த����� �� ᫥�. ������樨
  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);
  return 1;
}
