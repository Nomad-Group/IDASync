/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"

static bool flow;               // flow stop flag

//----------------------------------------------------------------------
// handle using/changing of operands
static void near TouchArg(op_t & x, int isAlt, int isload)
{
  ea_t ea = toEA(codeSeg(x.addr, x.n), x.addr);

  switch (x.type)
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
      doImmd(cmd.ea);
      // if not forced and marked as offset
      if (!isAlt && isOff(uFlag, x.n))
      {
        // it's an offset
        if ( x.dtyp == dt_word )
          ea &= 0xFFFF;
        else if ( x.dtyp == dt_byte )
          ea &= 0xFF;
        ua_add_dref(x.offb, ea, dr_O);
      }
      break;

    // jump or call
    case o_near:
      if (InstrIsSet(cmd.itype, CF_CALL))
      {
        // add cross-reference
        ua_add_cref(x.offb, ea, fl_CN);
        // doesn't return?
        flow = func_does_return(ea);
      }
      else
      {
        ua_add_cref(x.offb, ea, fl_JN);
      }
      break;

    // memory reference
    case o_mem:
      // make data at target address
      ua_dodata2(x.offb, ea, x.dtyp);
      if ( !isload )
        doVar(ea);
      // add xref to memory
      ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
      break;

    // other - report error
    default:
    badTouch:
      warning("%a %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
// emulator
int idaapi CR16_emu(void)
{
  uint32 Feature = cmd.get_canon_feature();

  // get operand types
  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);

  flow = ((Feature & CF_STOP) == 0);

  // handle reads
  if (Feature & CF_USE1)
    TouchArg(cmd.Op1, flag1, 1);
  if (Feature & CF_USE2)
    TouchArg(cmd.Op2, flag2, 1);

  if (Feature & CF_JUMP)
    QueueSet(Q_jumps, cmd.ea);

  // handle writes
  if (Feature & CF_CHG1)
    TouchArg(cmd.Op1, flag1, 0);
  if (Feature & CF_CHG2)
    TouchArg(cmd.Op2, flag2, 0);
  // if not stopping, add flow xref
  if (flow)
    ua_add_cref(0, cmd.ea + cmd.size, fl_F);

  return 1;
}
