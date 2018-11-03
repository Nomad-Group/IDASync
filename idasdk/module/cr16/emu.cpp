/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"

static bool flow;               // flow stop flag

//----------------------------------------------------------------------
// handle using/changing of operands
static void handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  ea_t ea = map_code_ea(insn, x);

  switch ( x.type )
  {
    // nothing to do
    case o_void:
    case o_reg:
    case o_displ:
      break;

    // immediate operand
    case o_imm:
      // can't be changed
      if ( !isload )
        goto badTouch;
      set_immd(insn.ea);
      // if not forced and marked as offset
      if ( !is_forced && is_off(get_flags(insn.ea), x.n) )
      {
        // it's an offset
        if ( x.dtype == dt_word )
          ea &= 0xFFFF;
        else if ( x.dtype == dt_byte )
          ea &= 0xFF;
        insn.add_dref(ea, x.offb, dr_O);
      }
      break;

    // jump or call
    case o_near:
      if ( has_insn_feature(insn.itype, CF_CALL) )
      {
        // add cross-reference
        insn.add_cref(ea, x.offb, fl_CN);
        // doesn't return?
        flow = func_does_return(ea);
      }
      else
      {
        insn.add_cref(ea, x.offb, fl_JN);
      }
      break;

    // memory reference
    case o_mem:
      // make data at target address
      insn.create_op_data(ea, x);
      // add xref to memory
      insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      break;

    // other - report error
    default:
    badTouch:
      warning("%a %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
// emulator
int idaapi CR16_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();

  // get operand types
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);

  flow = ((Feature & CF_STOP) == 0);

  // handle reads
  if ( Feature & CF_USE1 )
    handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 )
    handle_operand(insn, insn.Op2, flag2, true);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  // handle writes
  if ( Feature & CF_CHG1 )
    handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 )
    handle_operand(insn, insn.Op2, flag2, false);
  // if not stopping, add flow xref
  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}
