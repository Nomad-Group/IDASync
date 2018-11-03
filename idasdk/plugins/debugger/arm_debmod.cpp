#include <pro.h>
#include <nalt.hpp>
#include "arm_debmod.h"

#ifdef ENABLE_LOWCNDS
inline bool has_armv5(void) { return true; }
static arm_debmod_t *ssmod; // pointer to the current debugger module
#endif

#include "../../module/arm/opinfo.cpp"

#include "deb_arm.hpp"

//--------------------------------------------------------------------------
arm_debmod_t::arm_debmod_t()
{
  static const uchar bpt[] = ARM_BPT_CODE;
  bpt_code.append(bpt, sizeof(bpt));
  sp_idx = R_SP;
  pc_idx = R_PC;
  nregs = qnumber(arm_registers);

  is_xscale = false;
  databpts[0] = databpts[1] = BADADDR;
  codebpts[0] = codebpts[1] = BADADDR;
  dbcon = 0;
  dbptypes[0] = dbptypes[1] = -1;
  cbptypes[0] = cbptypes[1] = -1;
  set_platform("linux");
}


//--------------------------------------------------------------------------
int idaapi arm_debmod_t::dbg_is_ok_bpt(bpttype_t type, ea_t /*ea*/, int len)
{
  if ( type == BPT_SOFT )
    return BPT_OK;

  if ( !is_xscale )
    return BPT_BAD_TYPE; // hardware bpts are supported only for xScale

  // For some reason hardware instruction breakpoints do not work
  if ( type == BPT_EXEC )
    return BPT_BAD_TYPE;

  if ( len > 4 )
    return BPT_BAD_LEN;

  bool ok = type == BPT_EXEC
    ? (codebpts[0] == BADADDR || codebpts[1] == BADADDR)
    : (databpts[0] == BADADDR || databpts[1] == BADADDR);

  return ok ? BPT_OK : BPT_TOO_MANY;
}

//--------------------------------------------------------------------------
bool arm_debmod_t::add_hwbpt(bpttype_t type, ea_t ea, int len)
{
  //  msg("add_hwbpt %d %a %d\n", type, ea, len);
  if ( !is_xscale || len > 4 )
    return false;

  if ( !init_hwbpt_support() )
    return false;

  if ( type == BPT_EXEC )
  {
    if ( codebpts[0] != BADADDR && codebpts[1] != BADADDR )
      return false;

    int slot = codebpts[0] != BADADDR;
    codebpts[slot] = ea;
    cbptypes[slot] = type;
  }
  else
  {
    if ( databpts[0] != BADADDR && databpts[1] != BADADDR )
      return false;

    int slot = databpts[0] != BADADDR;
    int bits;
    switch ( type )
    {
    case BPT_WRITE:
      bits = 1;               // store only
      break;
    case BPT_RDWR:
      bits = 2;               // load/store
      break;
      //      BPT_READ:               // load only
      //        bits = 3;
      //        break;
    default:
      return false;
    }
    databpts[slot] = ea;
    dbptypes[slot] = type;
    dbcon |= bits << (slot*2);
  }
  return enable_hwbpts();
}

//--------------------------------------------------------------------------
bool arm_debmod_t::del_hwbpt(ea_t ea, bpttype_t type)
{
  //  msg("del_hwbpt %a\n", ea);
  if ( databpts[0] == ea && dbptypes[0] == type )
  {
    databpts[0] = BADADDR;
    dbcon &= ~3;
  }
  else if ( databpts[1] == ea && dbptypes[1] == type )
  {
    databpts[1] = BADADDR;
    dbcon &= ~(3<<2);
  }
  else if ( codebpts[0] == ea && cbptypes[0] == type )
  {
    codebpts[0] = BADADDR;
  }
  else if ( codebpts[1] == ea && cbptypes[1] == type )
  {
    codebpts[1] = BADADDR;
  }
  else
  {
    return false;
  }
  return enable_hwbpts();
}

//--------------------------------------------------------------------------
void arm_debmod_t::cleanup_hwbpts()
{
  databpts[0] = BADADDR;
  databpts[1] = BADADDR;
  codebpts[0] = BADADDR;
  codebpts[1] = BADADDR;
  dbcon = 0;
  // disable all bpts
  if ( is_xscale )
    disable_hwbpts();
}

//--------------------------------------------------------------------------
int arm_debmod_t::finalize_appcall_stack(
        call_context_t &ctx,
        regval_map_t &regs,
        bytevec_t &/*stk*/)
{
  regs[R_LR].ival = ctx.ctrl_ea;
  // return addrsize as the adjustment factor to add to sp
  // we do not need the return address, that's why we ignore the first 4
  // bytes of the prepared stack image
  return debapp_attrs.addrsize;
}

//--------------------------------------------------------------------------
int arm_debmod_t::get_regidx(const char *regname, int *clsmask)
{
// parallel arrays, must be edited together: arm_debmod_t::get_regidx()
//                                           register_info_t arm_registers[]
  static const char *const regnames[] =
  {
#ifndef __EA64__
    "R0",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "SP",
    "LR",
    "PC",
    "PSR",
    /* Floating point registers ********************************/
    // "VFP0",
    // "VFP1",
    // "VFP2",
    // "VFP3",
    // "VFP4",
    // "VFP5",
    // "VFP6",
    // "VFP7",
    // "SCR",
    // "EXC",
    /* VFP registers *******************************************/
    "D0",
    "D1",
    "D2",
    "D3",
    "D4",
    "D5",
    "D6",
    "D7",
    "D8",
    "D9",
    "D10",
    "D11",
    "D12",
    "D13",
    "D14",
    "D15",
    "D16",
    "D17",
    "D18",
    "D19",
    "D20",
    "D21",
    "D22",
    "D23",
    "D24",
    "D25",
    "D26",
    "D27",
    "D28",
    "D29",
    "D30",
    "D31",
    "FPSCR",
#else
    "X0",
    "X1",
    "X2",
    "X3",
    "X4",
    "X5",
    "X6",
    "X7",
    "X8",
    "X9",
    "X10",
    "X11",
    "X12",
    "X13",
    "X14",
    "X15",
    "X16",
    "X17",
    "X18",
    "X19",
    "X20",
    "X21",
    "X22",
    "X23",
    "X24",
    "X25",
    "X26",
    "X27",
    "X28",
    "X29",
    "X30",
    "SP",
    "PC",
    "PSR",
#endif
  };

  for ( int i=0; i < qnumber(regnames); i++ )
  {
    if ( stricmp(regname, regnames[i]) == 0 )
    {
      if ( clsmask != NULL )
#ifdef __HAVE_ARM_VFP__
      {
        if ( i < R_D0 )
          *clsmask = ARM_RC_GENERAL;
        else
          *clsmask = ARM_RC_VFP;
      }
#else
      {
        *clsmask = ARM_RC_GENERAL;
      }
#endif
      return i + R_R0;
    }
  }
  return -1;
}

#ifdef ENABLE_LOWCNDS
//--------------------------------------------------------------------------
static const regval_t &idaapi arm_getreg(const char *name, const regval_t *regvals)
{
  int idx = ssmod->get_regidx(name, NULL);
  QASSERT(30182, idx >= 0 && idx < ssmod->nregs);
  return regvals[idx];
}

//--------------------------------------------------------------------------
static uint32 idaapi arm_get_long(ea_t ea)
{
  uint32 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v));
  return v;
}

//--------------------------------------------------------------------------
static uint16 idaapi arm_get_word(ea_t ea)
{
  uint16 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v));
  return v;
}

//--------------------------------------------------------------------------
static uint8 idaapi arm_get_byte(ea_t ea)
{
  uint8 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v));
  return v;
}

//----------------------------------------------------------------------
// stripped down version of get_dtyp_size()
static size_t idaapi arm_get_dtyp_size(char dtype)
{
  switch ( dtype )
  {
    case dt_byte:    return 1;          // 8 bit
    case dt_word:    return 2;          // 16 bit
    case dt_dword:
    case dt_float:   return 4;          // 4 byte
    case dt_qword:
    case dt_double:  return 8;          // 8 byte
    default:         return 0;
  }
}

//--------------------------------------------------------------------------
// since arm does not have a single step facility, we have to emulate it
// with a temporary breakpoint.
int arm_debmod_t::dbg_perform_single_step(debug_event_t *dev, const insn_t &insn)
{
  // read register values
  regvals_t values;
  values.resize(nregs);
  int code = dbg_read_registers(dev->tid, ARM_RC_GENERAL, values.begin());
  if ( code <= 0 )
    return code;

  static const opinfo_helpers_t oh =
  {
    arm_getreg,
    arm_get_byte,
    arm_get_word,
    arm_get_long,
    arm_get_dtyp_size,
    NULL,               // has_insn_feature not needed
  };

  // calculate the address of the next executed instruction
  lock_begin();
  ssmod = this;
  ea_t next = calc_next_exec_insn(insn, values.begin(), oh, false); // TODO pass is_mprofile parameter
  ssmod = NULL;
  lock_end();

  // BADADDR means that the execution flow is linear
  if ( next == BADADDR )
  {
    next = insn.ea + insn.size;
    if ( (values[R_PSR].ival & BIT5) != 0 ) // thumb?
      next |= 1;
  }

  // safety check: self jumping instruction can not be single stepped
  if ( (next & ~1) == insn.ea )
    return 0;

  // add a breakpoint there
  update_bpt_info_t ubi;
  ubi.ea = next;
  ubi.type = BPT_SOFT;
  ubi.code = 0;
  code = dbg_update_bpts(&ubi, 1, 0);
  if ( code <= 0 )
    return code;

  code = resume_app_and_get_event(dev);

  // clean up: delete the temporary breakpoint
  ubi.ea &= ~1; // del_bpt requires an even address
  if ( dbg_update_bpts(&ubi, 0, 1) <= 0 )
  {
    msg("%a: failed to remove single step bpt?!\n", ubi.ea);
    if ( code > 0 )
      code = 0;
  }
  // the caller expects to see STEP after us:
  if ( code > 0 )
    dev->eid = STEP;
  return code;
}

#endif // ENABLE_LOWCNDS

//--------------------------------------------------------------------------
int arm_debmod_t::read_bpt_orgbytes(ea_t *p_ea, int *p_len, uchar *buf, int bufsize)
{
  ea_t &ea = *p_ea;
  if ( (ea & 1) != 0 ) // T bit is set, use a thumb breakpoint
  {
    ea--;
    *p_len = 2;
  }
  return inherited::read_bpt_orgbytes(p_ea, p_len, buf, bufsize);
}
