/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

static bool flow;        // 䫠��� �⮯�
//----------------------------------------------------------------------
// ���⠢�� �ᯮ�짮�����/��������� ���࠭���
static void handle_operand(
        const insn_t &insn,
        const op_t &x,
        bool is_forced,
        bool isload)
{
  ea_t ea = map_code_ea(insn, x);
  switch ( x.type )
  {
    // �� ���� �� �ᯮ������ !
    case o_void:
      break;
    // ��� ⮦� ��祣� ������
    case o_reg:
      break;

    // �����।�⢥��� ���࠭�
    case o_imm:   // �����।�⢥��� �� ����� ��������
      if ( !isload )
        goto badTouch;
      // ���⠢�� 䫠��� �����।�⢥����� ���࠭��
      set_immd(insn.ea);
      // �᫨ �� ���஢�� � ����祭 ᬥ饭���
      if ( !is_forced && is_off(get_flags(insn.ea), x.n) )
        insn.add_dref(ea, x.offb, dr_O); // �� ᬥ饭�� !
      break;

  // ���室 ��� �맮�
  case o_near:  // �� �맮� ? (��� ���室)
    if ( has_insn_feature(insn.itype, CF_CALL) )
    {
      // ���⠢�� ��뫪� �� ���
      insn.add_cref(ea, x.offb, fl_CN);
      // �� �㭪�� ��� ������ ?
      flow = func_does_return(ea);
    }
    else
    {
      insn.add_cref(ea, x.offb, fl_JN);
    }
    break;

  // ��뫪� �� �祩�� �����
  case o_mem:   // ᤥ���� ����� �� 㪠������� �����
    insn.create_op_data(ea, x);
    // ������� ��뫪� �� ������
    insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
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
int idaapi C39_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();
  // ����稬 ⨯� ���࠭���
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  // ����⨬ ��뫪� ���� ���࠭���
  if ( Feature & CF_USE1) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_USE3) handle_operand(insn, insn.Op3, flag3, true);
  // ���⠢�� ���室 � ��।�
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP,insn.ea);

  // ���⠢�� ���������
  if ( Feature & CF_CHG1) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2) handle_operand(insn, insn.Op2, flag2, false);
  if ( Feature & CF_CHG3) handle_operand(insn, insn.Op3, flag3, false);
  // �᫨ �� �⮯ - �த����� �� ᫥�. ������樨
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}
