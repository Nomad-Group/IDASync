/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

static bool flow;        // флажок стопа
//----------------------------------------------------------------------
// поставим использование/изменение операндов
static void handle_operand(
        const insn_t &insn,
        const op_t &x,
        bool is_forced,
        bool isload)
{
  ea_t ea = map_code_ea(insn, x);
  switch ( x.type )
  {
    // эта часть не используется !
    case o_void:
      break;
    // тут тоже нечего делать
    case o_reg:
      break;

    // непосредственный операнд
    case o_imm:   // непосредственный не может меняться
      if ( !isload )
        goto badTouch;
      // поставим флажок непосредственного операнда
      set_immd(insn.ea);
      // если не форсирован и помечен смещением
      if ( !is_forced && is_off(get_flags(insn.ea), x.n) )
        insn.add_dref(ea, x.offb, dr_O); // это смещение !
      break;

  // переход или вызов
  case o_near:  // это вызов ? (или переход)
    if ( has_insn_feature(insn.itype, CF_CALL) )
    {
      // поставим ссылку на код
      insn.add_cref(ea, x.offb, fl_CN);
      // это функция без возврата ?
      flow = func_does_return(ea);
    }
    else
    {
      insn.add_cref(ea, x.offb, fl_JN);
    }
    break;

  // ссылка на ячейку памяти
  case o_mem:   // сделаем данные по указанному адресу
    insn.create_op_data(ea, x);
    // добавим ссылку на память
    insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
    break;

  // прочее - сообщим ошибку
  default:
badTouch:
    warning("%a %s,%d: bad optype %d",
            insn.ea, insn.get_canon_mnem(),
            x.n, x.type);
    break;
  }
}

//----------------------------------------------------------------------
// емулятер
int idaapi C39_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();
  // получим типы операндов
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  // пометим ссылки двух операндов
  if ( Feature & CF_USE1) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_USE3) handle_operand(insn, insn.Op3, flag3, true);
  // поставим переход в очередь
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP,insn.ea);

  // поставим изменения
  if ( Feature & CF_CHG1) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2) handle_operand(insn, insn.Op2, flag2, false);
  if ( Feature & CF_CHG3) handle_operand(insn, insn.Op3, flag3, false);
  // если не стоп - продолжим на след. инструкции
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}
