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
// Конвертирование в данные(указан адресс) по указанному типу,
// добавить крос референсы для текущей инструкции
void DataSet(const insn_t &insn, const op_t &x, ea_t EA, int isload)
{
  // Конвертирование в данные(указан адресс) по указанному типу
  insn.create_op_data(EA, x);
  //добавить крос референсы для текущей инструкции
  insn.add_dref(EA, x.offb, isload ? dr_R : dr_W);
}
//----------------------------------------------------------------------
static void handle_operand(const op_t &x,int isAlt,int isload, const insn_t &insn)
{
  switch ( x.type )
  {
    case o_phrase:
      //Добавляем в список ошибок(выводим сообщение)
      //ошибку и адресс где это случилось
      //remember_problem(PR_JUMP, insn.ea);
    case o_void:
    case o_reg:
      break;

    case o_imm:
      //Установить для данного байта признак immedia
      set_immd(insn.ea);
      //Получить флаг для указанного линейного адресса
      if ( !isAlt )
      {
        ushort addr = ushort(x.addr);
        if ( x.type == o_displ )
        {
          addr += (ushort)insn.ip;
          addr += insn.size;
          //Получить линейный адресс
          uint32 offb = map_code_ea(insn, addr, x.n);
          DataSet(insn, x, offb, isload);
        }
        else if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        {
REREF:
          ea_t target = insn.add_off_drefs(x, dr_O, 0);
          if ( x.type == o_displ && target != BADADDR )
            //Преобразовать данные по указанному линейному адрессу в указанный тип
            insn.create_op_data(target, x);
        }
        else if ( x.type == o_displ
               && !x.reg
               && !is_defarg(get_flags(insn.ea), x.n )
               && op_plain_offset(insn.ea, x.n, to_ea(insn.cs,0)) )
        {
          goto REREF;
        }
      }
      break;

    case o_bit:
    case o_mem:
      // Конвертирование в данные(указан адресс) по указанному типу,
      //добавить крос референсы для текущей инструкции
      DataSet(insn, x, map_code_ea(insn, x), isload);
      break;

    case o_near:
      {
        //Получить линейный адресс
        ea_t ea = to_ea(insn.cs, x.addr);
        //Проверить является ли значение по указанному линейному адрессу - инструкцией
        int iscall = has_insn_feature(insn.itype, CF_CALL);
        //добавить крос референсы для текущей инструкции
        insn.add_cref(ea, x.offb, iscall ? fl_CN : fl_JN);
        if ( iscall )
          flow = func_does_return(ea);
      }
      break;

    default:
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(), x.n, x.type);
      break;
  }
}
//----------------------------------------------------------------------

int idaapi emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();
  flow = (Feature & CF_STOP) == 0;

  int flag1 = is_forced_operand(insn.ea, 0);
  int flag2 = is_forced_operand(insn.ea, 1);
  int flag3 = is_forced_operand(insn.ea, 2);

  if ( Feature & CF_USE1 ) handle_operand(insn.Op1, flag1, 1, insn);
  if ( Feature & CF_USE2 ) handle_operand(insn.Op2, flag2, 1, insn);
  if ( Feature & CF_USE3 ) handle_operand(insn.Op3, flag3, 1, insn);
  if ( Feature & CF_CHG1 ) handle_operand(insn.Op1, flag1, 0, insn);
  if ( Feature & CF_CHG2 ) handle_operand(insn.Op2, flag2, 0, insn);
  if ( Feature & CF_CHG3 ) handle_operand(insn.Op3, flag3, 0, insn);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}
//----------------------------------------------------------------------
